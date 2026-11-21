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
