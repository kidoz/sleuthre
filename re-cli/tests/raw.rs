use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn raw(fixture: &str, args: &[&str]) -> Output {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../re-core/tests/fixtures");
    Command::new(env!("CARGO_BIN_EXE_re-cli"))
        .arg("raw")
        .arg(fixtures.join(fixture))
        .args(args)
        .output()
        .unwrap()
}

fn instructions(output: Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn maps_two_file_slices_and_preserves_the_gap() {
    let regions = ["--region", "low:0:4:0x1000", "--region", "high:4:4:0x8000"];
    let options = [
        "--arch",
        "mips",
        "--byte-order",
        "little",
        "--entry",
        "0x8001",
    ];
    let output = raw("two-regions.raw", &[&regions[..], &options].concat());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "MIPS, entry=0x8001, byte order=Little",
        "low: file offset 0x0, length 0x4, start 0x1000",
        "high: file offset 0x4, length 0x4, start 0x8000",
    ] {
        assert!(summary.contains(expected), "{summary}");
    }
    // x86 can decode a single byte, so the CLI can inspect even the tail of a region.
    for (address, expected) in [
        ("0x1001", Some("42")),
        ("0x8001", Some("46")),
        ("0x1004", None),
    ] {
        let options = [
            "--arch", "x86", "--entry", address, "--count", "1", "--json",
        ];
        let result = instructions(raw("two-regions.raw", &[&regions[..], &options].concat()));
        assert_eq!(
            result.first().map(|i| i["bytes"].as_str().unwrap()),
            expected
        );
    }
}

#[test]
fn rejects_overlapping_or_malformed_mappings() {
    let common = ["--arch", "mips", "--region", "low:0:4:0x1000"];
    for (extra, messages) in [
        (
            ["--region", "high:4:4:0x1002"],
            &["overlaps", "'low'", "'high'"][..],
        ),
        (
            ["--region", "high:4:5:0x8000"],
            &["high", "exceeds input size"],
        ),
        (["--region", "high:four:4:0x8000"], &["invalid file offset"]),
        (["--region", "high:4:4"], &["NAME:FILE_OFFSET:LENGTH:START"]),
        (["--base", "0x2000"], &["--base", "--region"]),
        (["--byte-order", "unknown"], &["little or big"]),
    ] {
        let output = raw("two-regions.raw", &[&common[..], &extra].concat());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        for msg in messages {
            assert!(error.contains(msg), "{error}");
        }
    }
}

#[test]
fn decodes_four_byte_mips_regions_in_the_selected_order() {
    // Both halves encode addiu $t0, $zero, 1, in opposite byte orders.
    for (order, region, address) in [
        ("little", "code:0:4:0x1000", "0x1000"),
        ("big", "code:4:4:0x8000", "0x8000"),
    ] {
        let decoded = instructions(raw(
            "mips-addiu.raw",
            &[
                "--arch",
                "mips",
                "--region",
                region,
                "--byte-order",
                order,
                "--json",
            ],
        ));
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0]["address"], address);
        assert_eq!(decoded[0]["mnemonic"], "addiu");
        assert_eq!(decoded[0]["operands"], "$t0, $zero, 1");
    }
}

#[test]
fn base_maps_the_whole_file_with_an_optional_entry() {
    let decoded = instructions(raw(
        "two-regions.raw",
        &[
            "--arch", "x86", "--base", "0x4000", "--entry", "0x4007", "--count", "1", "--json",
        ],
    ));
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0]["address"], "0x4007");
    assert_eq!(decoded[0]["bytes"], "48");
}

#[test]
fn mips_defaults_preserve_legacy_decoding_and_the_region_loader_default() {
    for (option, value, expected) in [
        ("--base", "0x1000", "01 00 08 24"),
        ("--region", "code:4:4:0x1000", "24 08 00 01"),
    ] {
        let decoded = instructions(raw(
            "mips-addiu.raw",
            &["--arch", "mips", option, value, "--count", "1", "--json"],
        ));
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0]["bytes"], expected);
        assert_eq!(decoded[0]["mnemonic"], "addiu");
        assert_eq!(decoded[0]["operands"], "$t0, $zero, 1");
    }
}
