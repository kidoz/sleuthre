use std::path::Path;
use std::process::Command;

#[test]
fn triage_matches_the_reference_report_on_each_run() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../re-core/tests/fixtures/triage.pe");
    let expected = include_str!("../../re-core/tests/fixtures/triage.json");
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_re-cli"))
            .arg("triage")
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::str::from_utf8(&output.stdout).unwrap(), expected);
    }
}

#[test]
fn markdown_export_matches_the_fixture() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../re-core/tests/fixtures/triage.pe");
    let output = Command::new(env!("CARGO_BIN_EXE_re-cli"))
        .args(["triage", "--format", "markdown"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::str::from_utf8(&output.stdout).unwrap(),
        include_str!("../../re-core/tests/fixtures/triage.md")
    );
}

fn two_region_command(subcommand: &str) -> Command {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../re-core/tests/fixtures/two-regions.raw");
    let mut command = Command::new(env!("CARGO_BIN_EXE_re-cli"));
    command.arg(subcommand).arg(fixture);
    command
}

const EIGHT_BYTE_SHA256: &str = "9ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283fc48";

#[test]
fn raw_triage_exports_the_same_mapped_regions_in_json_and_markdown() {
    let mut command = two_region_command("triage");
    command.args([
        "--arch",
        "mips",
        "--region",
        "high:4:4:0x8000",
        "--region",
        "low:0:4:0x1000",
        "--byte-order",
        "little",
        "--entry",
        "0x8001",
    ]);
    let run = |cmd: &mut Command| {
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let first = run(&mut command);
    assert_eq!(first, run(&mut command));
    let report: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(report["sha256"], EIGHT_BYTE_SHA256);
    assert_eq!(report["format"], "Raw");
    assert_eq!(report["architecture"], "MIPS");
    assert_eq!(report["byte_order"], "Little");
    assert_eq!(report["entry_point"], "0x8001");
    let segments = report["segments"].as_array().unwrap();
    assert_eq!(segments.len(), 2);
    let md = run(command.args(["--format", "markdown"]));
    for field in [
        EIGHT_BYTE_SHA256,
        "Raw (MIPS)",
        "Byte order: Little",
        "Entry point: `0x8001`",
    ] {
        assert!(md.contains(field), "{md}");
    }
    for (seg, (name, offset, start)) in segments
        .iter()
        .zip([("low", 0, "0x1000"), ("high", 4, "0x8000")])
    {
        assert_eq!(seg["name"], name);
        assert_eq!(seg["file_offset"], offset);
        assert_eq!(seg["start"], start);
        assert_eq!(seg["size"], 4);
        let row = md
            .lines()
            .find(|line| line.contains(&format!("{start}  \"{name}\"")))
            .unwrap();
        assert!(
            row.contains("4 bytes") && row.contains(&format!("file offset {offset:#x}")),
            "{row}"
        );
    }
}

#[test]
fn raw_and_triage_report_the_same_overlap() {
    let error = |cmd| {
        let output = two_region_command(cmd)
            .args([
                "--arch",
                "mips",
                "--region",
                "low:0:4:0x1000",
                "--region",
                "high:4:4:0x1002",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success() && output.stdout.is_empty());
        String::from_utf8(output.stderr).unwrap()
    };
    let raw = error("raw");
    assert!(raw.contains("overlaps"));
    assert_eq!(error("triage"), raw);
}

#[test]
fn partial_and_whole_file_mappings_hash_all_original_bytes() {
    for (flag, value, offset, length, order) in [
        ("--region", "tail:4:4:0x9000", 4, 4, "Big"),
        ("--base", "0x9000", 0, 8, "Little"),
    ] {
        let output = two_region_command("triage")
            .args(["--arch", "mips", flag, value])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["sha256"], EIGHT_BYTE_SHA256);
        assert_eq!(report["entropy"], 3.0);
        assert_eq!(report["entry_point"], "0x9000");
        assert_eq!(report["byte_order"], order);
        assert_eq!(report["segments"][0]["file_offset"], offset);
        assert_eq!(report["segments"][0]["size"], length);
    }
}
