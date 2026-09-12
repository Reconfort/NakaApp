//! Path routing.
//!
//! Patterns use `{name}` for one segment and `{name...}` for a trailing
//! catch-all. Matching is exact and ordered: the first pattern that matches
//! wins, so more specific routes are registered first.
//!
//! Routing is intentionally dumb — no regex, no priority scoring. The agent has
//! about sixty routes and every one of them should be obvious from reading the
//! table.

use crate::{Method, Request, Response, Status};
use std::collections::BTreeMap;
use std::sync::Arc;

pub type Params = BTreeMap<String, String>;

/// Handlers receive the shared state as an `Arc` rather than a reference so a
/// handler that spawns work — a WebSocket session, a log follower — can keep
/// the state alive past the request that started it.
type Handler<S> = Arc<dyn Fn(&Arc<S>, Request) -> Response + Send + Sync>;

struct Route<S> {
    method: Method,
    segments: Vec<Segment>,
    handler: Handler<S>,
    /// Route reads the body itself (upload). The server will not buffer it.
    streaming_body: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Literal(String),
    Param(String),
    /// Captures the rest of the path, including slashes.
    Rest(String),
}

fn parse_pattern(pattern: &str) -> Vec<Segment> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(inner) = s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                if let Some(name) = inner.strip_suffix("...") {
                    Segment::Rest(name.to_string())
                } else {
                    Segment::Param(inner.to_string())
                }
            } else {
                Segment::Literal(s.to_string())
            }
        })
        .collect()
}

pub struct Router<S> {
    routes: Vec<Route<S>>,
}

impl<S: Send + Sync + 'static> Default for Router<S> {
    fn default() -> Self {
        Router::new()
    }
}

impl<S: Send + Sync + 'static> Router<S> {
    pub fn new() -> Self {
        Router { routes: Vec::new() }
    }

    pub fn route(
        mut self,
        method: Method,
        pattern: &str,
        handler: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.routes.push(Route {
            method,
            segments: parse_pattern(pattern),
            handler: Arc::new(handler),
            streaming_body: false,
        });
        self
    }

    /// Register a route whose handler reads the request body itself.
    pub fn route_streaming_body(
        mut self,
        method: Method,
        pattern: &str,
        handler: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.routes.push(Route {
            method,
            segments: parse_pattern(pattern),
            handler: Arc::new(handler),
            streaming_body: true,
        });
        self
    }

    pub fn get(self, p: &str, h: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static) -> Self {
        self.route(Method::Get, p, h)
    }
    pub fn post(self, p: &str, h: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static) -> Self {
        self.route(Method::Post, p, h)
    }
    pub fn put(self, p: &str, h: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static) -> Self {
        self.route(Method::Put, p, h)
    }
    pub fn patch(self, p: &str, h: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static) -> Self {
        self.route(Method::Patch, p, h)
    }
    pub fn delete(self, p: &str, h: impl Fn(&Arc<S>, Request) -> Response + Send + Sync + 'static) -> Self {
        self.route(Method::Delete, p, h)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Find a handler. Returns the params it captured and whether the body
    /// should be left unread for the handler to stream.
    pub(crate) fn lookup(&self, method: Method, path: &str) -> Lookup<S> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut path_matched = false;

        for route in &self.routes {
            if let Some(params) = match_segments(&route.segments, &parts) {
                if route.method == method
                    || (method == Method::Head && route.method == Method::Get)
                {
                    return Lookup::Found {
                        handler: route.handler.clone(),
                        params,
                        streaming_body: route.streaming_body,
                    };
                }
                path_matched = true;
            }
        }

        if path_matched {
            let allowed: Vec<&str> = self
                .routes
                .iter()
                .filter(|r| match_segments(&r.segments, &parts).is_some())
                .map(|r| r.method.as_str())
                .collect();
            Lookup::MethodNotAllowed(allowed.join(", "))
        } else {
            Lookup::NotFound
        }
    }

    /// Dispatch, translating a miss into the standard error envelope.
    pub fn dispatch(&self, state: &Arc<S>, mut req: Request) -> Response {
        match self.lookup(req.method, &req.uri.path) {
            Lookup::Found { handler, params, .. } => {
                req.params = params;
                handler(state, req)
            }
            Lookup::MethodNotAllowed(allow) => Response::error(
                Status::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                format!("{} is not supported on this path", req.method),
            )
            .header("Allow", allow),
            Lookup::NotFound => Response::error(
                Status::NOT_FOUND,
                "not_found",
                "No such endpoint on this agent",
            ),
        }
    }
}

pub(crate) enum Lookup<S> {
    Found { handler: Handler<S>, params: Params, streaming_body: bool },
    MethodNotAllowed(String),
    NotFound,
}

fn match_segments(pattern: &[Segment], parts: &[&str]) -> Option<Params> {
    let mut params = Params::new();
    let mut i = 0;
    for seg in pattern {
        match seg {
            Segment::Literal(lit) => {
                if parts.get(i) != Some(&lit.as_str()) {
                    return None;
                }
                i += 1;
            }
            Segment::Param(name) => {
                let value = parts.get(i)?;
                params.insert(name.clone(), (*value).to_string());
                i += 1;
            }
            Segment::Rest(name) => {
                // A catch-all may legitimately capture nothing: `/files/` with
                // no trailing path means the filesystem root.
                let rest = parts[i.min(parts.len())..].join("/");
                params.insert(name.clone(), rest);
                return Some(params);
            }
        }
    }
    if i == parts.len() { Some(params) } else { None }
}
