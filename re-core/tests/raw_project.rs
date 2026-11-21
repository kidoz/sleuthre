use re_core::analysis::pipeline::analyze_loaded;
use re_core::arch::{Architecture, Endianness};
use re_core::loader::{BinaryFormat, RawRegion, load_raw_regions};
use re_core::project::Project;
use std::path::PathBuf;

fn project_path() -> PathBuf {
    std::env::temp_dir().join(format!("raw_project_{}.slre", uuid::Uuid::new_v4()))
}

#[test]
fn two_raw_regions_survive_save_and_reopen() {
    let path = project_path();
    let source = path.with_extension("raw");
    let bytes = b"ABCDEFGH";
    std::fs::write(&source, bytes).unwrap();
    let regions = [
        RawRegion {
            name: "high".into(),
            file_offset: 4,
            length: 4,
            start: 0x8000,
        },
        RawRegion {
            name: "low".into(),
            file_offset: 0,
            length: 4,
            start: 0x1000,
        },
    ];
    let loaded = load_raw_regions(
        bytes,
        &regions,
        Architecture::Mips,
        Endianness::Little,
        Some(0x8001),
    )
    .unwrap();
    {
        let mut project = analyze_loaded(&source, loaded, |_| {}).unwrap().project;
        project.view_address = Some(0x1002);
        project.save_new(&path).unwrap();
    }
    std::fs::remove_file(source).unwrap();
    let reopened = Project::load(&path).unwrap();
    assert_eq!(reopened.binary_format, BinaryFormat::Raw);
    assert_eq!(reopened.arch, Architecture::Mips);
    assert_eq!(reopened.view_address, Some(0x1002));
    assert_eq!(reopened.memory_map.get_data(0x1001, 1), Some(&b"B"[..]));
    assert_eq!(reopened.memory_map.get_data(0x8001, 1), Some(&b"F"[..]));
    assert!(reopened.memory_map.segment_at(0x1004).is_none());
    let mapping = reopened.raw_mapping.as_ref().unwrap();
    assert_eq!(mapping.entry_point, 0x8001);
    assert_eq!(mapping.endianness, Endianness::Little);
    assert_eq!(mapping.source.file_size, 8);
    assert_eq!(
        reopened.memory_map.read_u16(0x8000, mapping.endianness),
        Some(0x4645)
    );
    for region in &regions {
        let segment = reopened.memory_map.segment_at(region.start).unwrap();
        assert_eq!(segment.name, region.name);
        assert_eq!(segment.start, region.start);
        assert_eq!(segment.size, region.length as u64);
        assert_eq!(
            mapping.source.file_offsets[&segment.start],
            region.file_offset as u64
        );
    }
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

fn copy_legacy_project() -> PathBuf {
    // Created with Project::save at tag v0.7.1 from a four-byte MIPS raw image.
    // Only the disposable copy is passed to SQLite, which may migrate on open.
    let path = project_path();
    {
        let mut file = std::fs::File::create_new(&path).unwrap();
        let fixture = include_bytes!("fixtures/raw-v0.7.1.slre.gz");
        std::io::copy(&mut flate2::read::GzDecoder::new(&fixture[..]), &mut file).unwrap();
    }
    path
}

#[test]
fn project_written_by_v0_7_1_opens_and_resaves() {
    let path = copy_legacy_project();
    for pass in 0..2 {
        let mut project = Project::load(&path).unwrap();
        assert_eq!(project.binary_format, BinaryFormat::Raw);
        assert_eq!(project.arch, Architecture::Mips);
        assert!(project.raw_mapping.is_none());
        assert!(project.triage_report.is_none());
        assert_eq!(project.memory_map.get_data(0x1000, 4), Some(&b"ABCD"[..]));
        assert_eq!(project.comments[&0x1001], "legacy annotation");
        if pass == 0 {
            project.save(&path).unwrap();
        }
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn legacy_project_preserves_annotation_and_originless_pending_proposal() {
    // v0.7.1 saved annotations but did not yet write the proposal queue.
    let path = copy_legacy_project();
    let id = uuid::Uuid::new_v4();
    let pending = serde_json::json!([{
        "id": id, "kind": {"Comment": {"address": 4097, "new_comment": "replacement"}},
        "rationale": "peer note", "confidence": 0.9
    }]);
    re_core::db::Database::open(&path)
        .unwrap()
        .set_metadata("pending_actions", &pending.to_string())
        .unwrap();
    for pass in 0..2 {
        let mut project = Project::load(&path).unwrap();
        assert_eq!(project.comments[&0x1001], "legacy annotation");
        assert_eq!(project.pending_actions.len(), 1);
        let proposal = &project.pending_actions[0];
        assert_eq!(proposal.id, id);
        assert_eq!(proposal.origin, re_core::project::ProposalOrigin::Unknown);
        assert_eq!(proposal.confidence, Some(0.9));
        assert!(project.review_history.is_empty());
        assert_eq!(proposal.rationale, "peer note");
        assert!(matches!(&proposal.kind,
            re_core::project::ActionKind::Comment { address: 0x1001, new_comment } if new_comment == "replacement"));
        if pass == 0 {
            project.save(&path).unwrap();
        }
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn reopen_rejects_inconsistent_raw_mapping() {
    let path = copy_legacy_project();
    for (start, offset, reason) in [
        (0x1004, 0, "Missing raw file offset"),
        (0x1000, 1, "Invalid raw file range"),
        (0x1000, u64::MAX, "Invalid raw file range"),
    ] {
        let value = serde_json::json!({
            "source": { "file_size": 4, "file_offsets": { (start.to_string()): offset } },
            "entry_point": 4096,
            "endianness": "Little"
        });
        re_core::db::Database::open(&path)
            .unwrap()
            .set_metadata("raw_mapping", &value.to_string())
            .unwrap();
        let err = Project::load(&path)
            .err()
            .expect("invalid provenance should fail to load");
        assert!(err.to_string().contains(reason), "{err}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn original_report_survives_a_partial_mapping_and_later_edits() {
    use re_core::analysis::pipeline::{AnalysisMode, analyze_file_with_triage};

    let path = project_path();
    let bytes = include_bytes!("fixtures/two-regions.raw");
    let load = |data: &[u8]| {
        load_raw_regions(
            data,
            &[RawRegion {
                name: "high".into(),
                file_offset: 4,
                length: 4,
                start: 0x8000,
            }],
            Architecture::Mips,
            Endianness::Little,
            None,
        )
    };
    let source = path.with_extension("raw");
    std::fs::write(&source, bytes).unwrap();
    let (result, report) =
        analyze_file_with_triage(&source, AnalysisMode::Normal, None, |_| {}, load).unwrap();
    let mut project = result.project;
    project.triage_report = Some(report.into());
    project.save_new(&path).unwrap();
    std::fs::remove_file(source).unwrap();
    drop(project);

    let mut reopened = Project::load(&path).unwrap();
    reopened.memory_map.write_data(0x8000, b"aaaa").unwrap();
    reopened.autosave().unwrap();
    drop(reopened);
    let reopened = Project::load(&path).unwrap();
    let report = reopened.triage_report.as_ref().unwrap();
    assert_eq!(reopened.memory_map.get_data(0x8000, 4), Some(&b"aaaa"[..]));
    assert_eq!(
        report.sha256,
        "9ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283fc48"
    );
    assert_eq!(report.entropy, 3.0);
    assert_eq!(report.segments[0].file_offset, Some(4));
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn invalid_saved_report_returns_a_project_error() {
    let path = copy_legacy_project();
    for (field, value, reason) in [
        (
            "entry_point",
            serde_json::json!("0x10000000000000000"),
            "Invalid triage report",
        ),
        (
            "schema_version",
            serde_json::json!(2),
            "Unsupported triage report version",
        ),
        (
            "entropy",
            serde_json::json!(9.0),
            "Invalid triage report header",
        ),
    ] {
        let mut report: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/two-regions.json")).unwrap();
        report[field] = value;
        re_core::db::Database::open(&path)
            .unwrap()
            .set_metadata("triage_report", &report.to_string())
            .unwrap();
        let err = Project::load(&path)
            .err()
            .expect("invalid report should fail to load");
        assert!(err.to_string().contains(reason), "{err}");
    }
    std::fs::remove_file(path).unwrap();
}
