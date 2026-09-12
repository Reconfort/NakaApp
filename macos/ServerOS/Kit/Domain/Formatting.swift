//  Formatting.swift
//  ServerOS
//
//  Every number a person reads passes through here.
//
//  Consistency matters more than cleverness: if storage is "240 GB" on the
//  dashboard it must not be "223.5 GiB" on the detail screen. So there is one
//  function per kind of quantity, and views are expected to call it rather than
//  interpolating a raw value.
//
//  Units follow the convention the rest of the platform uses — decimal (GB) for
//  storage, because that is what `Finder`, disk manufacturers and `df -H` all
//  say, and because a user comparing ServerOS to their hosting panel should see
//  the same number.

import Foundation

public enum Formatting {

    // MARK: - Bytes

    private static let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file       // decimal: 1 KB = 1000 bytes
        f.allowsNonnumericFormatting = false
        f.zeroPadsFractionDigits = false
        return f
    }()

    /// "1.2 GB". Used everywhere a size is shown.
    public static func bytes(_ value: Int64) -> String {
        guard value >= 0 else { return "—" }
        return byteFormatter.string(fromByteCount: value)
    }

    public static func bytes(_ value: Int64?) -> String {
        value.map(bytes) ?? "—"
    }

    /// "1.2 MB/s". Rates are always per second in this product.
    public static func rate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return "—" }
        if bytesPerSecond < 1 { return "0 B/s" }
        return "\(bytes(Int64(bytesPerSecond)))/s"
    }

    /// "240 GB of 500 GB" — the phrasing used under every usage bar.
    public static func usage(used: Int64?, total: Int64?) -> String {
        switch (used, total) {
        case let (.some(u), .some(t)):
            return "\(bytes(u)) of \(bytes(t))"
        case let (.none, .some(t)):
            return "\(bytes(t)) total"
        default:
            return "Size unknown"
        }
    }

    // MARK: - Numbers

    /// "61%" — whole numbers, because a tenth of a percent of memory is noise.
    public static func percent(_ value: Double) -> String {
        guard value.isFinite else { return "—" }
        return "\(Int(value.rounded()))%"
    }

    public static func percent(_ value: Double?) -> String {
        value.map(percent) ?? "—"
    }

    /// "0.42" — load averages and ratios, where the decimals carry meaning.
    public static func decimal(_ value: Double, places: Int = 2) -> String {
        guard value.isFinite else { return "—" }
        return String(format: "%.\(places)f", value)
    }

    /// "1,284" — counts, grouped so four digits are readable at a glance.
    public static func count(_ value: Int) -> String {
        integerFormatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }

    public static func count(_ value: Int64) -> String {
        integerFormatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }

    private static let integerFormatter: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.maximumFractionDigits = 0
        return f
    }()

    // MARK: - Time

    /// "2 days", "3 hours", "8 minutes" — one unit, the largest that fits.
    ///
    /// Uptime and "last seen" read better as a single approximate unit than as
    /// "2d 3h 14m 6s", which nobody parses at a glance.
    public static func duration(seconds: Int) -> String {
        let s = max(0, seconds)
        switch s {
        case 0..<60:
            return s == 1 ? "1 second" : "\(s) seconds"
        case 60..<3600:
            let m = s / 60
            return m == 1 ? "1 minute" : "\(m) minutes"
        case 3600..<86_400:
            let h = s / 3600
            return h == 1 ? "1 hour" : "\(h) hours"
        case 86_400..<2_592_000:
            let d = s / 86_400
            return d == 1 ? "1 day" : "\(d) days"
        default:
            let months = s / 2_592_000
            return months == 1 ? "1 month" : "\(months) months"
        }
    }

    public static func duration(seconds: Int64) -> String {
        duration(seconds: Int(clamping: seconds))
    }

    /// "2d 3h" — the compact form, for table cells where space is tight.
    public static func durationCompact(seconds: Int) -> String {
        let s = max(0, seconds)
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m" }
        if s < 86_400 {
            let h = s / 3600, m = (s % 3600) / 60
            return m > 0 ? "\(h)h \(m)m" : "\(h)h"
        }
        let d = s / 86_400, h = (s % 86_400) / 3600
        return h > 0 ? "\(d)d \(h)h" : "\(d)d"
    }

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f
    }()

    /// "4 minutes ago". The activity feed's entire vocabulary.
    public static func relative(_ date: Date, now: Date = Date()) -> String {
        // Anything inside a few seconds reads better as "just now" than as
        // "in 0 seconds", which is what the formatter produces around zero.
        let delta = now.timeIntervalSince(date)
        if abs(delta) < 5 { return "just now" }
        return relativeFormatter.localizedString(for: date, relativeTo: now)
    }

    public static func relative(unixSeconds: Int64, now: Date = Date()) -> String {
        relative(Date(timeIntervalSince1970: TimeInterval(unixSeconds)), now: now)
    }

    private static let timestampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    /// "12 Sep 2026 at 09:15" — absolute time, for tooltips and detail rows.
    public static func timestamp(_ date: Date) -> String {
        timestampFormatter.string(from: date)
    }

    public static func timestamp(unixSeconds: Int64?) -> String {
        guard let unixSeconds, unixSeconds > 0 else { return "—" }
        return timestamp(Date(timeIntervalSince1970: TimeInterval(unixSeconds)))
    }

    private static let logTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// "09:15:42" — the gutter of the log viewer.
    public static func logTime(unixSeconds: Int64?) -> String {
        guard let unixSeconds, unixSeconds > 0 else { return "--:--:--" }
        return logTimeFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(unixSeconds)))
    }

    // MARK: - Text

    /// "nginx, postgres and 3 others" — for a health reason that must not run
    /// to three lines when twelve things are wrong.
    public static func list(_ items: [String], limit: Int = 3) -> String {
        guard !items.isEmpty else { return "" }
        if items.count == 1 { return items[0] }
        if items.count <= limit {
            let head = items.dropLast().joined(separator: ", ")
            return "\(head) and \(items[items.count - 1])"
        }
        let shown = items.prefix(limit).joined(separator: ", ")
        let rest = items.count - limit
        return "\(shown) and \(rest) other\(rest == 1 ? "" : "s")"
    }

    /// Truncate on a word boundary with a real ellipsis.
    public static func truncate(_ text: String, to maxLength: Int) -> String {
        guard text.count > maxLength else { return text }
        let cut = text.prefix(maxLength)
        if let lastSpace = cut.lastIndex(of: " "), cut.distance(from: cut.startIndex, to: lastSpace) > maxLength / 2 {
            return "\(cut[cut.startIndex..<lastSpace])…"
        }
        return "\(cut)…"
    }

    /// `0644` from a raw mode, for the file inspector.
    public static func fileMode(_ octal: UInt32?) -> String {
        guard let octal else { return "—" }
        return String(format: "%04o", octal & 0o7777)
    }

    /// `-rw-r--r--` from a raw mode — the form anyone who has run `ls -l`
    /// reads instantly.
    public static func modeString(_ octal: UInt32?, isDirectory: Bool, isSymlink: Bool) -> String {
        guard let octal else { return "—" }
        let type = isSymlink ? "l" : (isDirectory ? "d" : "-")
        var out = type
        let bits = [
            (octal & 0o400, "r"), (octal & 0o200, "w"), (octal & 0o100, "x"),
            (octal & 0o040, "r"), (octal & 0o020, "w"), (octal & 0o010, "x"),
            (octal & 0o004, "r"), (octal & 0o002, "w"), (octal & 0o001, "x"),
        ]
        for (bit, char) in bits {
            out += bit != 0 ? char : "-"
        }
        return out
    }

    /// A container's state in the product's words rather than Docker's.
    public static func containerState(_ state: String, status: String) -> String {
        switch state {
        case "running": return status.isEmpty ? "Running" : status
        case "paused": return "Paused"
        case "restarting": return "Restarting"
        case "created": return "Created, not started"
        case "exited", "dead": return status.isEmpty ? "Stopped" : status
        default: return state.capitalizingFirstLetter()
        }
    }

    /// A Linux process state letter in words.
    public static func processState(_ state: String) -> String {
        switch state {
        case "running": return "Running"
        case "sleeping": return "Sleeping"
        case "disk-sleep": return "Waiting on disk"
        case "stopped": return "Stopped"
        case "zombie": return "Zombie"
        case "idle": return "Idle"
        default: return state.capitalizingFirstLetter()
        }
    }
}
