//! A deliberately small regular-expression engine for log filtering.
//!
//! # Why write one at all
//!
//! Log filtering wants more than substring matching (`^\[error\]`, `GET /api/.*
//! 5[0-9][0-9]`), and this workspace takes no third-party dependencies. The
//! alternative — shelling out to `grep` — would hand a caller-supplied string
//! to another program, which is exactly the architecture this agent exists to
//! avoid.
//!
//! # Why it is small on purpose
//!
//! A full regex engine is a denial-of-service surface. `(a+)+$` against sixty
//! `a`s takes longer than the heat death of the datacentre in any backtracking
//! implementation, and the caller supplying it is a customer typing into a
//! search box. Rather than implement a linear-time engine, this subset removes
//! the *ability to express* catastrophic backtracking: there are no groups, so
//! there is nothing to nest a quantifier inside, and a quantifier may never
//! follow another quantifier. A step budget ([`MAX_STEPS`]) is the backstop.
//!
//! # The supported subset, exactly
//!
//! | syntax      | meaning                                                  |
//! |-------------|----------------------------------------------------------|
//! | `abc`       | literal characters                                        |
//! | `.`         | any single character                                      |
//! | `*` `+` `?` | greedy repetition of the **single** preceding atom        |
//! | `[a-z]`     | character class: ranges, single characters                |
//! | `[^a-z]`    | negated class                                             |
//! | `^` `$`     | anchors, valid only at the start/end of a branch          |
//! | `\|`        | alternation between whole branches                        |
//! | `\x`        | escape: the next character, literally                     |
//!
//! Everything else is **rejected with an explanation**, not silently treated as
//! a literal: `(`, `)`, `{`, `}`, a quantifier with nothing before it, a
//! quantifier after a quantifier, an unterminated class, a trailing backslash,
//! a pattern longer than [`MAX_PATTERN_BYTES`], or one with more than
//! [`MAX_NODES`] atoms or [`MAX_QUANTIFIERS`] quantifiers. A rejection is a
//! [`FsError::InvalidPattern`] whose message names the rule, so the app can
//! show it under the search box.
//!
//! Matching is a **search**, not a full match, unless anchors say otherwise,
//! and it is case-sensitive.

use crate::error::FsError;

/// Longest pattern accepted.
pub const MAX_PATTERN_BYTES: usize = 256;

/// Most atoms a single branch may compile to.
pub const MAX_NODES: usize = 128;

/// Most quantified atoms a single branch may contain.
pub const MAX_QUANTIFIERS: usize = 16;

/// Backstop on matching work per line. Exhausting it is reported as "no match"
/// rather than as an error: one pathological line must not fail the request.
pub const MAX_STEPS: usize = 50_000;

/// How many times an atom may repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quant {
    One,
    ZeroOrOne,
    ZeroOrMore,
    OneOrMore,
}

/// One element of a character class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassItem {
    Char(char),
    Range(char, char),
}

/// What a single position can match.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    Literal(char),
    Any,
    Class { negated: bool, items: Vec<ClassItem> },
}

impl Atom {
    fn matches(&self, c: char) -> bool {
        match self {
            Atom::Literal(l) => *l == c,
            // `.` matching a newline is irrelevant here (input is one line at a
            // time) and matching it keeps the semantics simple.
            Atom::Any => true,
            Atom::Class { negated, items } => {
                let hit = items.iter().any(|item| match item {
                    ClassItem::Char(x) => *x == c,
                    ClassItem::Range(lo, hi) => *lo <= c && c <= *hi,
                });
                hit != *negated
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    atom: Atom,
    quant: Quant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Branch {
    anchored_start: bool,
    anchored_end: bool,
    nodes: Vec<Node>,
}

/// A compiled pattern from the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    branches: Vec<Branch>,
    source: String,
}

impl Pattern {
    /// Compile, or explain why the pattern is not in the subset.
    pub fn compile(pattern: &str) -> Result<Pattern, FsError> {
        if pattern.is_empty() {
            return Err(invalid("the pattern is empty"));
        }
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(invalid(format!(
                "it is {} bytes long and the limit is {MAX_PATTERN_BYTES}",
                pattern.len()
            )));
        }
        let mut branches = Vec::new();
        for raw in split_branches(pattern) {
            branches.push(compile_branch(raw)?);
        }
        Ok(Pattern { branches, source: pattern.to_owned() })
    }

    /// The pattern as the caller wrote it.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Does any branch match anywhere in `text`?
    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let mut steps = MAX_STEPS;
        for branch in &self.branches {
            if branch_matches(branch, &chars, &mut steps) {
                return true;
            }
        }
        false
    }
}

/// Split on `|` at the top level, honouring escapes and character classes.
fn split_branches(pattern: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_class = false;
    let mut escaped = false;
    for (i, c) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '[' => in_class = true,
            ']' => in_class = false,
            '|' if !in_class => {
                out.push(&pattern[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&pattern[start..]);
    out
}

fn compile_branch(raw: &str) -> Result<Branch, FsError> {
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0usize;
    let mut anchored_start = false;
    let mut anchored_end = false;
    let mut nodes: Vec<Node> = Vec::new();
    let mut quantifiers = 0usize;

    if chars.first() == Some(&'^') {
        anchored_start = true;
        i = 1;
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            '^' => {
                return Err(invalid("^ is only allowed at the start of a pattern"));
            }
            '$' => {
                if i + 1 != chars.len() {
                    return Err(invalid("$ is only allowed at the end of a pattern"));
                }
                anchored_end = true;
                i += 1;
            }
            '(' | ')' => return Err(invalid("groups are not supported")),
            '{' | '}' => return Err(invalid("repetition counts like {2,3} are not supported")),
            '*' | '+' | '?' => {
                let quant = match c {
                    '*' => Quant::ZeroOrMore,
                    '+' => Quant::OneOrMore,
                    _ => Quant::ZeroOrOne,
                };
                let Some(last) = nodes.last_mut() else {
                    return Err(invalid(format!("{c} has nothing before it to repeat")));
                };
                if last.quant != Quant::One {
                    // The rule that makes catastrophic backtracking
                    // inexpressible: `a**`, `a+?`, `.*+` are all refused.
                    return Err(invalid("a repetition cannot follow another repetition"));
                }
                last.quant = quant;
                quantifiers += 1;
                if quantifiers > MAX_QUANTIFIERS {
                    return Err(invalid(format!(
                        "it uses more than {MAX_QUANTIFIERS} repetitions"
                    )));
                }
                i += 1;
            }
            '.' => {
                nodes.push(Node { atom: Atom::Any, quant: Quant::One });
                i += 1;
            }
            '[' => {
                let (atom, next) = compile_class(&chars, i)?;
                nodes.push(Node { atom, quant: Quant::One });
                i = next;
            }
            '\\' => {
                let Some(&escaped) = chars.get(i + 1) else {
                    return Err(invalid("it ends with a lone backslash"));
                };
                nodes.push(Node { atom: Atom::Literal(escaped), quant: Quant::One });
                i += 2;
            }
            _ => {
                nodes.push(Node { atom: Atom::Literal(c), quant: Quant::One });
                i += 1;
            }
        }
        if nodes.len() > MAX_NODES {
            return Err(invalid(format!("it is more than {MAX_NODES} elements long")));
        }
    }

    Ok(Branch { anchored_start, anchored_end, nodes })
}

/// Parse `[...]` starting at `open`, returning the atom and the index after it.
fn compile_class(chars: &[char], open: usize) -> Result<(Atom, usize), FsError> {
    let mut i = open + 1;
    let mut negated = false;
    if chars.get(i) == Some(&'^') {
        negated = true;
        i += 1;
    }
    let mut items: Vec<ClassItem> = Vec::new();
    // A `]` immediately after `[` or `[^` is a literal, as in POSIX.
    if chars.get(i) == Some(&']') {
        items.push(ClassItem::Char(']'));
        i += 1;
    }
    while i < chars.len() {
        match chars[i] {
            ']' => {
                if items.is_empty() {
                    return Err(invalid("the character class [] is empty"));
                }
                return Ok((Atom::Class { negated, items }, i + 1));
            }
            '\\' => {
                let Some(&esc) = chars.get(i + 1) else {
                    return Err(invalid("it ends with a lone backslash"));
                };
                items.push(ClassItem::Char(esc));
                i += 2;
            }
            c => {
                // `a-z`, but a trailing `-` before `]` is a literal.
                if chars.get(i + 1) == Some(&'-')
                    && chars.get(i + 2).is_some_and(|n| *n != ']')
                {
                    let hi = chars[i + 2];
                    if hi < c {
                        return Err(invalid(format!("the range {c}-{hi} runs backwards")));
                    }
                    items.push(ClassItem::Range(c, hi));
                    i += 3;
                } else {
                    items.push(ClassItem::Char(c));
                    i += 1;
                }
            }
        }
    }
    Err(invalid("a character class is missing its closing ]"))
}

fn branch_matches(branch: &Branch, text: &[char], steps: &mut usize) -> bool {
    // Anchored at the start means exactly one candidate offset; otherwise the
    // search tries every offset, including one past the end so that `a*` can
    // match an empty tail.
    let last_start = if branch.anchored_start { 0 } else { text.len() };
    for start in 0..=last_start {
        if match_nodes(&branch.nodes, 0, text, start, branch.anchored_end, steps) {
            return true;
        }
        if *steps == 0 {
            return false;
        }
    }
    false
}

/// Greedy backtracking matcher. Recursion depth is bounded by [`MAX_NODES`].
fn match_nodes(
    nodes: &[Node],
    idx: usize,
    text: &[char],
    pos: usize,
    anchored_end: bool,
    steps: &mut usize,
) -> bool {
    if *steps == 0 {
        return false;
    }
    *steps -= 1;

    if idx == nodes.len() {
        return !anchored_end || pos == text.len();
    }
    let node = &nodes[idx];
    match node.quant {
        Quant::One => {
            if pos < text.len() && node.atom.matches(text[pos]) {
                match_nodes(nodes, idx + 1, text, pos + 1, anchored_end, steps)
            } else {
                false
            }
        }
        Quant::ZeroOrOne => {
            if pos < text.len()
                && node.atom.matches(text[pos])
                && match_nodes(nodes, idx + 1, text, pos + 1, anchored_end, steps)
            {
                return true;
            }
            match_nodes(nodes, idx + 1, text, pos, anchored_end, steps)
        }
        Quant::ZeroOrMore | Quant::OneOrMore => {
            let minimum = if node.quant == Quant::OneOrMore { 1 } else { 0 };
            let mut most = pos;
            while most < text.len() && node.atom.matches(text[most]) {
                most += 1;
            }
            if most - pos < minimum {
                return false;
            }
            // Greedy: longest first, then give characters back one at a time.
            let mut take = most;
            loop {
                if match_nodes(nodes, idx + 1, text, take, anchored_end, steps) {
                    return true;
                }
                if take == pos + minimum || *steps == 0 {
                    return false;
                }
                take -= 1;
            }
        }
    }
}

fn invalid(reason: impl Into<String>) -> FsError {
    FsError::InvalidPattern { reason: reason.into() }
}

/// A line filter: plain substring, or a compiled [`Pattern`].
///
/// Substring is the default because it is what a person means when they type
/// `timeout` into a search box, and because it cannot be made slow.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Case-sensitive substring search.
    Substring(String),
    /// The bounded regex subset.
    Regex(Pattern),
}

impl Matcher {
    /// Build a matcher, or `None` when there is nothing to filter by.
    pub fn new(filter: Option<&str>, regex: bool) -> Result<Option<Matcher>, FsError> {
        let Some(filter) = filter.filter(|f| !f.is_empty()) else { return Ok(None) };
        if regex {
            Ok(Some(Matcher::Regex(Pattern::compile(filter)?)))
        } else {
            if filter.len() > MAX_PATTERN_BYTES {
                return Err(invalid(format!(
                    "it is {} bytes long and the limit is {MAX_PATTERN_BYTES}",
                    filter.len()
                )));
            }
            Ok(Some(Matcher::Substring(filter.to_owned())))
        }
    }

    /// Does this line pass the filter?
    pub fn is_match(&self, line: &str) -> bool {
        match self {
            Matcher::Substring(needle) => line.contains(needle.as_str()),
            Matcher::Regex(p) => p.is_match(line),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, text: &str) -> bool {
        Pattern::compile(pattern).expect("pattern must compile").is_match(text)
    }

    fn rejected(pattern: &str) {
        match Pattern::compile(pattern) {
            Err(e) => assert_eq!(e.kind(), "invalid_pattern", "{pattern}: {e}"),
            Ok(_) => panic!("{pattern} should have been rejected"),
        }
    }

    // ---- accepted --------------------------------------------------------

    #[test]
    fn literal_search_is_unanchored() {
        assert!(m("timeout", "database timeout after 30s"));
        assert!(!m("timeout", "all good"));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(!m("ERROR", "error: bad"));
        assert!(m("error", "error: bad"));
    }

    #[test]
    fn dot_matches_any_character() {
        assert!(m("c.t", "cat"));
        assert!(m("c.t", "cut"));
        assert!(!m("c.t", "ct"));
    }

    #[test]
    fn star_is_zero_or_more() {
        assert!(m("ab*c", "ac"));
        assert!(m("ab*c", "abbbbc"));
        assert!(!m("^ab*c$", "abd"));
    }

    #[test]
    fn plus_is_one_or_more() {
        assert!(!m("^ab+c$", "ac"));
        assert!(m("ab+c", "abbc"));
    }

    #[test]
    fn question_is_zero_or_one() {
        assert!(m("^colou?r$", "color"));
        assert!(m("^colou?r$", "colour"));
        assert!(!m("^colou?r$", "colouur"));
    }

    #[test]
    fn classes_match_ranges() {
        assert!(m("[0-9][0-9][0-9]", "status 404 returned"));
        assert!(!m("^[0-9]+$", "40a"));
        assert!(m("[a-zA-Z_]+", "hello_world"));
    }

    #[test]
    fn negated_classes_work() {
        assert!(m("^[^0-9]+$", "abc"));
        assert!(!m("^[^0-9]+$", "ab3"));
    }

    #[test]
    fn a_literal_bracket_can_be_first_in_a_class() {
        assert!(m("[]]", "a ] b"));
    }

    #[test]
    fn a_trailing_dash_in_a_class_is_a_literal() {
        assert!(m("^[a-]+$", "a-a"));
    }

    #[test]
    fn anchors_pin_both_ends() {
        assert!(m("^GET", "GET /api HTTP/1.1"));
        assert!(!m("^GET", "POST /api"));
        assert!(m("HTTP/1.1$", "GET /api HTTP/1.1"));
        assert!(!m("HTTP/1.1$", "HTTP/1.1 200"));
    }

    #[test]
    fn alternation_tries_every_branch() {
        assert!(m("error|fatal", "fatal: out of memory"));
        assert!(m("error|fatal", "error: nope"));
        assert!(!m("error|fatal", "warning: hm"));
    }

    #[test]
    fn alternation_combines_with_anchors_per_branch() {
        assert!(m("^GET|^POST", "POST /x"));
        assert!(!m("^GET|^POST", "PUT /x"));
    }

    #[test]
    fn escaping_makes_a_metacharacter_literal() {
        assert!(m(r"\[error\]", "2026/09/12 [error] upstream down"));
        assert!(m(r"1\.1", "HTTP/1.1"));
        assert!(!m(r"^1\.1$", "1x1"));
    }

    #[test]
    fn a_realistic_nginx_five_hundred_filter() {
        let p = r#"" 5[0-9][0-9] "#;
        assert!(m(p, r#"10.0.0.1 - - [12/Sep/2026:09:15:00 +0000] "GET /api HTTP/1.1" 502 166"#));
        assert!(!m(p, r#"10.0.0.1 - - [12/Sep/2026:09:15:00 +0000] "GET /api HTTP/1.1" 200 166"#));
    }

    #[test]
    fn a_realistic_level_filter() {
        let p = r"^[0-9/: ]+\[error\]";
        assert!(m(p, "2026/09/12 09:15:00 [error] upstream timed out"));
        assert!(!m(p, "2026/09/12 09:15:00 [warn] upstream is slow"));
    }

    #[test]
    fn dot_star_between_literals() {
        assert!(m("GET.*500", "GET /api/users returned 500"));
        assert!(!m("GET.*500", "POST /api/users returned 500"));
    }

    #[test]
    fn an_empty_line_matches_only_permissive_patterns() {
        assert!(m("^$", ""));
        assert!(m("a*", ""));
        assert!(!m("a+", ""));
    }

    #[test]
    fn unicode_is_matched_by_character_not_byte() {
        assert!(m("caf.", "café"));
        assert!(m("^..$", "é€"));
    }

    #[test]
    fn a_long_but_legal_pattern_compiles() {
        let p = "a".repeat(MAX_NODES);
        assert!(Pattern::compile(&p).is_ok());
        assert!(Pattern::compile(&p).unwrap().is_match(&"a".repeat(MAX_NODES)));
    }

    // ---- rejected --------------------------------------------------------

    #[test]
    fn groups_are_rejected() {
        rejected("(ab)+");
        rejected("a(b");
        rejected("a)b");
    }

    #[test]
    fn repetition_counts_are_rejected() {
        rejected("a{2,3}");
        rejected("a{2}");
    }

    #[test]
    fn nested_quantifiers_are_rejected() {
        rejected("a**");
        rejected("a+*");
        rejected("a?+");
        rejected(".*+");
    }

    #[test]
    fn a_quantifier_with_nothing_to_repeat_is_rejected() {
        rejected("*abc");
        rejected("+abc");
        rejected("?abc");
        rejected("^*a");
    }

    #[test]
    fn an_unterminated_class_is_rejected() {
        rejected("[a-z");
        rejected("[");
    }

    #[test]
    fn an_empty_class_is_rejected() {
        rejected("[^]");
    }

    #[test]
    fn a_backwards_range_is_rejected() {
        rejected("[z-a]");
    }

    #[test]
    fn a_lone_trailing_backslash_is_rejected() {
        rejected(r"abc\");
    }

    #[test]
    fn a_misplaced_anchor_is_rejected() {
        rejected("a^b");
        rejected("a$b");
    }

    #[test]
    fn an_empty_pattern_is_rejected() {
        rejected("");
    }

    #[test]
    fn an_over_long_pattern_is_rejected() {
        rejected(&"a".repeat(MAX_PATTERN_BYTES + 1));
    }

    #[test]
    fn too_many_quantifiers_are_rejected() {
        rejected(&"a*".repeat(MAX_QUANTIFIERS + 1));
    }

    #[test]
    fn too_many_atoms_are_rejected() {
        rejected(&"a".repeat(MAX_NODES + 1));
    }

    // ---- resource bounds -------------------------------------------------

    #[test]
    fn a_pattern_that_would_backtrack_hard_still_returns_quickly() {
        // The classic (a+)+$ is inexpressible here, but a*a*a*…b is the
        // polynomial cousin and must still be bounded by the step budget.
        let p = Pattern::compile("a*a*a*a*a*a*a*b").unwrap();
        let text = "a".repeat(64);
        let started = std::time::Instant::now();
        assert!(!p.is_match(&text));
        assert!(started.elapsed().as_millis() < 500, "took {:?}", started.elapsed());
    }

    #[test]
    fn the_step_budget_never_reports_a_false_positive() {
        let p = Pattern::compile(".*.*.*.*.*.*x").unwrap();
        assert!(!p.is_match(&"y".repeat(200)));
        assert!(p.is_match("x"));
    }

    // ---- matcher ---------------------------------------------------------

    #[test]
    fn matcher_defaults_to_substring() {
        let mm = Matcher::new(Some("a.c"), false).unwrap().unwrap();
        assert!(mm.is_match("xxa.cxx"));
        assert!(!mm.is_match("abc"), "a substring filter is not a regex");
    }

    #[test]
    fn matcher_compiles_a_regex_when_asked() {
        let mm = Matcher::new(Some("a.c"), true).unwrap().unwrap();
        assert!(mm.is_match("abc"));
    }

    #[test]
    fn matcher_is_none_when_there_is_no_filter() {
        assert!(Matcher::new(None, false).unwrap().is_none());
        assert!(Matcher::new(Some(""), true).unwrap().is_none());
    }

    #[test]
    fn matcher_rejects_a_bad_regex_with_an_explanation() {
        let e = Matcher::new(Some("(a)"), true).unwrap_err();
        assert_eq!(e.kind(), "invalid_pattern");
        assert!(e.to_string().contains("groups"), "{e}");
    }

    #[test]
    fn matcher_bounds_a_substring_filter_too() {
        let long = "x".repeat(MAX_PATTERN_BYTES + 1);
        assert!(Matcher::new(Some(&long), false).is_err());
    }

    #[test]
    fn source_is_kept_for_echoing_back() {
        assert_eq!(Pattern::compile("^GET").unwrap().source(), "^GET");
    }
}
