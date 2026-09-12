//  FormattingTests.swift
//  ServerOSTests
//
//  Every number a person reads passes through `Formatting`, so these are
//  assertions about what the UI literally says.
//
//  Where a formatter's output depends on the user's locale — thousands
//  separators, byte units, relative dates — the test asserts on the *decision*
//  rather than the exact glyphs: that zero is not spelled "Zero", that an
//  unknown value is an em dash rather than "0", that a rate ends in "/s". A
//  test that pinned "1,284" would fail in German and teach nothing.

import XCTest
@testable import ServerOS

final class FormattingTests: XCTestCase {

    // MARK: - Bytes

    func testBytesRendersAUnit() {
        XCTAssertTrue(Formatting.bytes(Int64(2_000_000_000)).contains("GB"))
        XCTAssertTrue(Formatting.bytes(Int64(5_000_000)).contains("MB"))
        XCTAssertTrue(Formatting.bytes(Int64(3_000)).contains("KB"))
    }

    func testBytesUsesDecimalUnitsLikeTheRestOfThePlatform() {
        // `.file` counts 1 KB as 1000 bytes, which is what Finder, disk
        // manufacturers and `df -H` all say. A user comparing ServerOS to their
        // hosting panel must see the same number.
        XCTAssertTrue(Formatting.bytes(Int64(1_000_000_000)).hasPrefix("1"))
        XCTAssertFalse(Formatting.bytes(Int64(1_000_000_000)).contains("GiB"))
    }

    func testZeroBytesIsNumericRatherThanSpelledOut() {
        let zero = Formatting.bytes(Int64(0))
        XCTAssertTrue(zero.contains("0"))
        XCTAssertFalse(zero.lowercased().contains("zero"), "allowsNonnumericFormatting must stay off")
    }

    func testUnknownSizesAreAnEmDashRatherThanZero() {
        // "The agent could not tell us" and "it is empty" are different facts.
        XCTAssertEqual(Formatting.bytes(nil), "—")
        XCTAssertEqual(Formatting.bytes(Int64(-1)), "—")
    }

    func testRate() {
        XCTAssertEqual(Formatting.rate(0), "0 B/s")
        XCTAssertEqual(Formatting.rate(0.4), "0 B/s")
        XCTAssertTrue(Formatting.rate(2_000_000).hasSuffix("/s"))
        XCTAssertEqual(Formatting.rate(-5), "—")
        XCTAssertEqual(Formatting.rate(Double.nan), "—")
        XCTAssertEqual(Formatting.rate(Double.infinity), "—")
    }

    func testUsagePhrasing() {
        XCTAssertTrue(Formatting.usage(used: 240_000_000_000, total: 500_000_000_000).contains(" of "))
        XCTAssertTrue(Formatting.usage(used: nil, total: 500_000_000_000).hasSuffix("total"))
        XCTAssertEqual(Formatting.usage(used: nil, total: nil), "Size unknown")
        XCTAssertEqual(Formatting.usage(used: 1_000, total: nil), "Size unknown")
    }

    // MARK: - Numbers

    func testPercentRoundsToWholeNumbers() {
        // A tenth of a percent of memory is noise.
        XCTAssertEqual(Formatting.percent(0), "0%")
        XCTAssertEqual(Formatting.percent(23.4), "23%")
        XCTAssertEqual(Formatting.percent(23.5), "24%")
        XCTAssertEqual(Formatting.percent(99.6), "100%")
        XCTAssertEqual(Formatting.percent(100), "100%")
    }

    func testPercentOfNothing() {
        XCTAssertEqual(Formatting.percent(nil), "—")
        XCTAssertEqual(Formatting.percent(Double.nan), "—")
        XCTAssertEqual(Formatting.percent(Double.infinity), "—")
    }

    func testDecimalKeepsThePlacesThatCarryMeaning() {
        XCTAssertEqual(Formatting.decimal(0.42), "0.42")
        XCTAssertEqual(Formatting.decimal(8), "8.00")
        XCTAssertEqual(Formatting.decimal(2.04, places: 1), "2.0")
        XCTAssertEqual(Formatting.decimal(Double.nan), "—")
    }

    func testCount() {
        XCTAssertEqual(Formatting.count(0), "0")
        XCTAssertEqual(Formatting.count(42), "42")
        // Grouped so four digits are readable at a glance; the separator itself
        // is the user's, not ours.
        XCTAssertGreaterThan(Formatting.count(1_284).count, 4)
        XCTAssertEqual(Formatting.count(Int64(7)), "7")
    }

    // MARK: - Duration

    func testDurationUsesOneUnit() {
        XCTAssertEqual(Formatting.duration(seconds: 0), "0 seconds")
        XCTAssertEqual(Formatting.duration(seconds: 1), "1 second")
        XCTAssertEqual(Formatting.duration(seconds: 59), "59 seconds")
        XCTAssertEqual(Formatting.duration(seconds: 60), "1 minute")
        XCTAssertEqual(Formatting.duration(seconds: 119), "1 minute")
        XCTAssertEqual(Formatting.duration(seconds: 200), "3 minutes")
        XCTAssertEqual(Formatting.duration(seconds: 3_599), "59 minutes")
        XCTAssertEqual(Formatting.duration(seconds: 3_600), "1 hour")
        XCTAssertEqual(Formatting.duration(seconds: 7_200), "2 hours")
        XCTAssertEqual(Formatting.duration(seconds: 86_400), "1 day")
        XCTAssertEqual(Formatting.duration(seconds: 172_800), "2 days")
        XCTAssertEqual(Formatting.duration(seconds: 2_592_000), "1 month")
        XCTAssertEqual(Formatting.duration(seconds: 7_776_000), "3 months")
    }

    func testNegativeDurationsDoNotProduceNonsense() {
        XCTAssertEqual(Formatting.duration(seconds: -30), "0 seconds")
    }

    func testDurationAcceptsTheAgentsInt64s() {
        XCTAssertEqual(Formatting.duration(seconds: Int64(11_873)), "3 hours")
    }

    func testCompactDurationForTightTableCells() {
        XCTAssertEqual(Formatting.durationCompact(seconds: 0), "0s")
        XCTAssertEqual(Formatting.durationCompact(seconds: 45), "45s")
        XCTAssertEqual(Formatting.durationCompact(seconds: 90), "1m")
        XCTAssertEqual(Formatting.durationCompact(seconds: 3_600), "1h")
        XCTAssertEqual(Formatting.durationCompact(seconds: 3_660), "1h 1m")
        XCTAssertEqual(Formatting.durationCompact(seconds: 86_400), "1d")
        XCTAssertEqual(Formatting.durationCompact(seconds: 90_000), "1d 1h")
    }

    // MARK: - Relative and absolute time

    func testAnythingWithinAFewSecondsReadsAsJustNow() {
        // The formatter says "in 0 seconds" around zero, which is nonsense on a
        // live dashboard.
        let now = Date()
        XCTAssertEqual(Formatting.relative(now, now: now), "just now")
        XCTAssertEqual(Formatting.relative(now.addingTimeInterval(-2), now: now), "just now")
        XCTAssertEqual(Formatting.relative(now.addingTimeInterval(2), now: now), "just now")
    }

    func testOlderTimesGetARelativePhrase() {
        let now = Date()
        let phrase = Formatting.relative(now.addingTimeInterval(-3_600), now: now)
        XCTAssertNotEqual(phrase, "just now")
        XCTAssertFalse(phrase.isEmpty)
    }

    func testRelativeAcceptsAgentTimestamps() {
        let now = Date(timeIntervalSince1970: 1_789_210_504)
        XCTAssertEqual(Formatting.relative(unixSeconds: 1_789_210_504, now: now), "just now")
    }

    func testAbsoluteTimestampsAndTheUnknownCase() {
        XCTAssertEqual(Formatting.timestamp(unixSeconds: nil), "—")
        XCTAssertEqual(Formatting.timestamp(unixSeconds: 0), "—")
        XCTAssertFalse(Formatting.timestamp(unixSeconds: 1_789_210_504).isEmpty)
    }

    func testLogGutterTime() {
        XCTAssertEqual(Formatting.logTime(unixSeconds: nil), "--:--:--")
        XCTAssertEqual(Formatting.logTime(unixSeconds: 0), "--:--:--")
        let rendered = Formatting.logTime(unixSeconds: 1_789_210_504)
        XCTAssertEqual(rendered.count, 8)
        XCTAssertEqual(rendered.filter { $0 == ":" }.count, 2)
    }

    // MARK: - Text

    func testListPhrasing() {
        XCTAssertEqual(Formatting.list([]), "")
        XCTAssertEqual(Formatting.list(["nginx"]), "nginx")
        XCTAssertEqual(Formatting.list(["nginx", "redis"]), "nginx and redis")
        XCTAssertEqual(Formatting.list(["nginx", "redis", "postgres"]), "nginx, redis and postgres")
        XCTAssertEqual(
            Formatting.list(["nginx", "redis", "postgres", "cron"]),
            "nginx, redis, postgres and 1 other"
        )
        XCTAssertEqual(
            Formatting.list(["a", "b", "c", "d", "e"]),
            "a, b, c and 2 others"
        )
    }

    func testListHonoursALowerLimit() {
        XCTAssertEqual(Formatting.list(["a", "b", "c"], limit: 2), "a, b and 1 other")
        XCTAssertEqual(Formatting.list(["a", "b"], limit: 2), "a and b")
    }

    func testTruncateBreaksOnAWordAndUsesARealEllipsis() {
        XCTAssertEqual(Formatting.truncate("short", to: 20), "short")
        let long = "the quick brown fox jumps over the lazy dog"
        let cut = Formatting.truncate(long, to: 20)
        XCTAssertTrue(cut.hasSuffix("…"))
        XCTAssertLessThanOrEqual(cut.count, 21)
        XCTAssertFalse(cut.contains("..."), "a real ellipsis, not three dots")
    }

    func testTruncateOnAStringWithNoSpaces() {
        let cut = Formatting.truncate(String(repeating: "x", count: 40), to: 10)
        XCTAssertEqual(cut, String(repeating: "x", count: 10) + "…")
    }

    // MARK: - File modes

    func testFileMode() {
        XCTAssertEqual(Formatting.fileMode(nil), "—")
        XCTAssertEqual(Formatting.fileMode(0o644), "0644")
        XCTAssertEqual(Formatting.fileMode(0o755), "0755")
        XCTAssertEqual(Formatting.fileMode(0o600), "0600")
        // The file-type bits above 0o7777 are not part of the permission mode.
        XCTAssertEqual(Formatting.fileMode(0o100_644), "0644")
    }

    func testModeStringReadsLikeLsMinusL() {
        XCTAssertEqual(Formatting.modeString(nil, isDirectory: false, isSymlink: false), "—")
        XCTAssertEqual(
            Formatting.modeString(0o644, isDirectory: false, isSymlink: false),
            "-rw-r--r--"
        )
        XCTAssertEqual(
            Formatting.modeString(0o755, isDirectory: true, isSymlink: false),
            "drwxr-xr-x"
        )
        XCTAssertEqual(
            Formatting.modeString(0o777, isDirectory: false, isSymlink: true),
            "lrwxrwxrwx"
        )
        XCTAssertEqual(
            Formatting.modeString(0o600, isDirectory: false, isSymlink: false),
            "-rw-------"
        )
        XCTAssertEqual(
            Formatting.modeString(0o000, isDirectory: false, isSymlink: false),
            "----------"
        )
        // A symlink wins over a directory in the type column, as `ls` does.
        XCTAssertEqual(
            Formatting.modeString(0o755, isDirectory: true, isSymlink: true),
            "lrwxr-xr-x"
        )
    }

    // MARK: - States in the product's words

    func testContainerStateUsesOurVocabulary() {
        XCTAssertEqual(Formatting.containerState("running", status: "Up 3 days"), "Up 3 days")
        XCTAssertEqual(Formatting.containerState("running", status: ""), "Running")
        XCTAssertEqual(Formatting.containerState("paused", status: ""), "Paused")
        XCTAssertEqual(Formatting.containerState("restarting", status: ""), "Restarting")
        XCTAssertEqual(Formatting.containerState("created", status: ""), "Created, not started")
        XCTAssertEqual(Formatting.containerState("exited", status: ""), "Stopped")
        XCTAssertEqual(Formatting.containerState("dead", status: "Exited (1)"), "Exited (1)")
        XCTAssertEqual(Formatting.containerState("weird", status: ""), "Weird")
    }

    func testProcessStateInWords() {
        XCTAssertEqual(Formatting.processState("running"), "Running")
        XCTAssertEqual(Formatting.processState("sleeping"), "Sleeping")
        XCTAssertEqual(Formatting.processState("disk-sleep"), "Waiting on disk")
        XCTAssertEqual(Formatting.processState("zombie"), "Zombie")
        XCTAssertEqual(Formatting.processState("idle"), "Idle")
        XCTAssertEqual(Formatting.processState("stopped"), "Stopped")
        XCTAssertEqual(Formatting.processState("tracing"), "Tracing")
    }

    func testCapitalisingFirstLetterLeavesTheRestAlone() {
        // Acronyms and product names must survive.
        XCTAssertEqual("nginx".capitalizingFirstLetter(), "Nginx")
        XCTAssertEqual("PostgreSQL".capitalizingFirstLetter(), "PostgreSQL")
        XCTAssertEqual("".capitalizingFirstLetter(), "")
        XCTAssertEqual("1 needs attention".capitalizingFirstLetter(), "1 needs attention")
    }
}
