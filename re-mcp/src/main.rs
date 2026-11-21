use anyhow::{Context, Result};
use re_core::analysis::cfg::ControlFlowGraph;
use re_core::analysis::pipeline::{AnalysisMode, analyze_file_with_triage};
use re_core::analysis::triage::ReportFormat;
use re_core::arch::{Architecture, Endianness};
use re_core::debuginfo;
use re_core::disasm::Disassembler;
use re_core::loader::{self, RawRegion};
use re_core::project::{ActionKind, PendingAction, Project};
use re_core::signatures::SignatureDatabase;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead};
use std::path::PathBuf;
use uuid::Uuid;

const MAX_SEARCH_RESULTS: u64 = 1000;
const MAX_DISASM_COUNT: usize = 1_000;
const MAX_TRIAGE_BYTES: usize = 8 * 1024 * 1024;

struct McpServer {
    project: Option<Project>,
    disasm: Option<Disassembler>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMapping {
    arch: Architecture,
    byte_order: Option<Endianness>,
    entry_point: Option<u64>,
    regions: Vec<RawRegion>,
}

impl RawMapping {
    fn schema() -> Value {
        json!({
            "type": "object",
            "description": "Map named file regions of a raw image. Offsets and lengths are in bytes.",
            "properties": {
                "arch": { "type": "string", "enum": ["x86", "x86_64", "arm", "arm64", "mips", "mips64", "riscv32", "riscv64"] },
                "byte_order": { "enum": ["little", "big", null], "description": "Defaults to the architecture's byte order." },
                "entry_point": { "type": ["integer", "null"], "minimum": 0, "description": "Defaults to the virtual start of the first region supplied." },
                "regions": {
                    "type": "array", "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "pattern": r"\S" },
                            "file_offset": { "type": "integer", "minimum": 0 },
                            "length": { "type": "integer", "minimum": 1 },
                            "start": { "type": "integer", "minimum": 0, "description": "Virtual start address." }
                        },
                        "required": ["name", "file_offset", "length", "start"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["arch", "regions"],
            "additionalProperties": false
        })
    }

    fn parse(value: &Value) -> Result<Self> {
        anyhow::ensure!(value.is_object(), "raw must be an object");
        anyhow::ensure!(
            value["arch"].is_string(),
            "raw.arch requires an architecture name"
        );
        anyhow::ensure!(
            value["byte_order"].is_null() || value["byte_order"].is_string(),
            "raw.byte_order must be little or big"
        );
        if let Some(regions) = value["regions"].as_array() {
            anyhow::ensure!(
                !regions.is_empty(),
                "raw.regions must contain at least one region"
            );
            anyhow::ensure!(
                regions.iter().all(Value::is_object),
                "each raw region must be an object"
            );
        }
        let mapping = Self::deserialize(value)?;
        for (index, region) in mapping.regions.iter().enumerate() {
            anyhow::ensure!(
                !region.name.trim().is_empty(),
                "raw.regions[{index}] requires a name"
            );
        }
        Ok(mapping)
    }
}

/// Bound the serialized tool text while writing, including JSON escaping.
struct ReportBuffer(Vec<u8>);

impl io::Write for ReportBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_TRIAGE_BYTES - self.0.len() {
            return Err(io::Error::other(
                "Report exceeds 8 MiB. Export it with re-cli triage.",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn propose(project: &mut Project, kind: ActionKind, rationale: String, id: &Value) -> Value {
    if project.pending_actions.len() >= 1024 {
        return json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32003,"message":"Proposal queue is full"}});
    }
    project.pending_actions.push(PendingAction {
        id: Uuid::new_v4(),
        kind,
        rationale,
        confidence: 0.9,
    });
    tool_text_result(
        id,
        "Change queued. Save the project and open the saved file in the GUI to review it.",
    )
}

/// Return a JSON-RPC invalid-params error if a required argument is missing.
fn missing_param_error(id: &Value, name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32602, "message": format!("Missing required parameter: {}", name) }
    })
}

/// Build a JSON-RPC tool result wrapping a plain text string.
fn tool_text_result(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [{ "type": "text", "text": text }] }
    })
}

/// Build a JSON-RPC tool result by serializing `data` to JSON text.
/// Returns a JSON-RPC error response if serialization fails.
fn tool_result(id: &Value, data: &impl serde::Serialize) -> Value {
    match serde_json::to_string(data) {
        Ok(text) => tool_text_result(id, &text),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32603, "message": format!("Serialization error: {}", e) }
        }),
    }
}

/// Build a JSON-RPC resource result by serializing `data` to JSON text.
/// Returns a JSON-RPC error response if serialization fails.
fn resource_result(id: &Value, uri: &str, data: &impl serde::Serialize) -> Value {
    match serde_json::to_string(data) {
        Ok(text) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "contents": [{ "uri": uri, "text": text }] }
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32603, "message": format!("Serialization error: {}", e) }
        }),
    }
}

/// Confine an MCP-initiated project save to the workspace of the opened
/// binary: the resolved target must live in (or under) the binary's directory
/// and carry the `.slre` extension, so a misbehaving client cannot overwrite
/// arbitrary files the server process can write (per the project threat
/// model, MCP tools never write outside the workspace).
fn confine_save_path(
    target: &std::path::Path,
    binary_path: &std::path::Path,
) -> Result<PathBuf, String> {
    if target.extension().and_then(|e| e.to_str()) != Some("slre") {
        return Err("save path must use the .slre extension".into());
    }
    let workspace = binary_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .canonicalize()
        .map_err(|e| format!("cannot resolve workspace: {}", e))?;
    let file_name = target
        .file_name()
        .ok_or_else(|| "save path has no file name".to_string())?;
    // Relative paths resolve against the workspace. Canonicalizing the
    // parent (symlinks and `..` resolved) before the containment check
    // closes both escape routes.
    let parent_candidate = match target.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => workspace.join(p),
        None => workspace.clone(),
    };
    let parent = parent_candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve save directory: {}", e))?;
    if !parent.starts_with(&workspace) {
        return Err(format!(
            "save path must stay inside the project workspace {}",
            workspace.display()
        ));
    }
    let resolved = parent.join(file_name);
    // Refuse to write through a pre-existing symlink at the final component.
    if resolved.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
        return Err("save path is a symlink".into());
    }
    Ok(resolved)
}

/// Format an LLIL function as a human-readable listing — one instruction per
/// line with its source address. Debug-format is used because LLIL does not
/// yet have a dedicated textual printer.
fn format_llil(func: &re_core::il::llil::LlilFunction) -> String {
    let mut out = String::new();
    out.push_str(&format!("; llil function @ 0x{:x}\n", func.entry));
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            out.push_str(&format!("{:08x}: {:?}\n", inst.address, stmt));
        }
    }
    out
}

/// Format an MLIL function (SSA form) as a listing.
fn format_mlil(func: &re_core::il::mlil::MlilFunction) -> String {
    let mut out = String::new();
    out.push_str(&format!("; mlil function @ 0x{:x}\n", func.entry));
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            out.push_str(&format!("{:08x}: {:?}\n", inst.address, stmt));
        }
    }
    out
}

/// Walk an MLIL function and return a sorted list of SSA variables together
/// with the addresses at which they appear.
fn collect_ssa_vars(func: &re_core::il::mlil::MlilFunction) -> Vec<serde_json::Value> {
    use re_core::il::mlil::{MlilExpr, MlilStmt};
    use std::collections::BTreeMap;

    fn walk_expr(expr: &MlilExpr, addr: u64, map: &mut BTreeMap<(String, u32), Vec<u64>>) {
        match expr {
            MlilExpr::Var(ssa) => {
                map.entry((ssa.name.clone(), ssa.version))
                    .or_default()
                    .push(addr);
            }
            MlilExpr::Load { addr: a, .. } => walk_expr(a, addr, map),
            MlilExpr::Cast { operand, .. } => walk_expr(operand, addr, map),
            MlilExpr::BinOp { left, right, .. } => {
                walk_expr(left, addr, map);
                walk_expr(right, addr, map);
            }
            MlilExpr::UnaryOp { operand, .. } => walk_expr(operand, addr, map),
            MlilExpr::Phi(vars) => {
                for v in vars {
                    map.entry((v.name.clone(), v.version))
                        .or_default()
                        .push(addr);
                }
            }
            MlilExpr::Call { target, args } => {
                walk_expr(target, addr, map);
                for a in args {
                    walk_expr(a, addr, map);
                }
            }
            MlilExpr::VectorOp { operands, .. } => {
                for op in operands {
                    walk_expr(op, addr, map);
                }
            }
            MlilExpr::Const(_) => {}
        }
    }

    let mut map: BTreeMap<(String, u32), Vec<u64>> = BTreeMap::new();
    for inst in &func.instructions {
        for stmt in &inst.stmts {
            match stmt {
                MlilStmt::Assign { dest, src } => {
                    map.entry((dest.name.clone(), dest.version))
                        .or_default()
                        .push(inst.address);
                    walk_expr(src, inst.address, &mut map);
                }
                MlilStmt::Store { addr, value, .. } => {
                    walk_expr(addr, inst.address, &mut map);
                    walk_expr(value, inst.address, &mut map);
                }
                MlilStmt::Jump { target } => walk_expr(target, inst.address, &mut map),
                MlilStmt::BranchIf { cond, target } => {
                    walk_expr(cond, inst.address, &mut map);
                    walk_expr(target, inst.address, &mut map);
                }
                MlilStmt::Call { target, args } => {
                    walk_expr(target, inst.address, &mut map);
                    for a in args {
                        walk_expr(a, inst.address, &mut map);
                    }
                }
                MlilStmt::Return | MlilStmt::Nop | MlilStmt::Unimplemented { .. } => {}
            }
        }
    }
    map.into_iter()
        .map(|((name, version), sites)| {
            json!({
                "name": name,
                "version": version,
                "sites": sites.into_iter().map(|a| format!("0x{:x}", a)).collect::<Vec<_>>(),
            })
        })
        .collect()
}

impl McpServer {
    fn new() -> Self {
        Self {
            project: None,
            disasm: None,
        }
    }

    fn handle_request(&mut self, request: Value) -> Value {
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                        "resources": {}
                    },
                    "serverInfo": { "name": "sleuthre-core", "version": env!("CARGO_PKG_VERSION") }
                }
            }),

            // --- Tool Management ---
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "open_binary",
                            "description": "Load a binary file (ELF/PE/Mach-O/raw) for analysis",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "path": { "type": "string" }, "raw": RawMapping::schema() },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "get_triage_report",
                            "description": "Return the opened sample's original triage report as UTF-8 text (up to 8 MiB).",
                            "annotations": { "readOnlyHint": true },
                            "inputSchema": {
                                "type": "object",
                                "properties": { "format": { "type": "string", "enum": ["json", "markdown"], "default": "json" } },
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "get_disasm",
                            "description": "Get disassembly listing at address",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "count": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "submit_rename",
                            "description": "Propose a new name for a function (requires user approval)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "name": { "type": "string" },
                                    "rationale": { "type": "string" }
                                },
                                "required": ["address", "name"]
                            }
                        },
                        {
                            "name": "get_xrefs",
                            "description": "Get cross-references for an address",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "direction": { "type": "string", "enum": ["to", "from", "both"] }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "add_comment",
                            "description": "Propose adding or removing a comment for GUI approval",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "text": { "type": "string" }
                                },
                                "required": ["address", "text"]
                            }
                        },
                        {
                            "name": "get_strings",
                            "description": "Get discovered strings from the binary",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filter": { "type": "string" },
                                    "limit": { "type": "number" }
                                }
                            }
                        },
                        {
                            "name": "get_cfg",
                            "description": "Get control flow graph for a function",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "save_project",
                            "description": "Save the current project to a file",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string" }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "get_decompilation",
                            "description": "Decompile a function at a given address into pseudocode",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "search_memory",
                            "description": "Search binary memory for byte patterns (hex bytes with ?? wildcards, e.g. '48 89 E5 ?? ??')",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pattern": { "type": "string" },
                                    "limit": { "type": "integer", "minimum": 0, "maximum": MAX_SEARCH_RESULTS }
                                },
                                "required": ["pattern"]
                            }
                        },
                        {
                            "name": "get_imports",
                            "description": "List imported functions, optionally filtered by name",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filter": { "type": "string" }
                                }
                            }
                        },
                        {
                            "name": "get_exports",
                            "description": "List exported functions, optionally filtered by name",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filter": { "type": "string" }
                                }
                            }
                        },
                        {
                            "name": "detect_patterns",
                            "description": "Run signature matching on the binary using built-in x86_64 signatures",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "run_analysis_passes",
                            "description": "Run all registered analysis passes (plugins) and return findings",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "get_bookmarks",
                            "description": "List all bookmarks as address-note pairs",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "add_bookmark",
                            "description": "Add a bookmark at an address with an optional note",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "note": { "type": "string" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "get_function_signature",
                            "description": "Get the typed function signature for a function at an address (from debug info or type libraries)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "load_pdb",
                            "description": "Load a PDB (Program Database) file to extract debug symbols for the current binary",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string" }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "get_source_line",
                            "description": "Get the source file and line number for an address (requires debug info)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "get_microcode",
                            "description": "Return the LLIL/MLIL textual microcode for the function containing the given address.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "tier": { "type": "string", "enum": ["llil", "mlil"], "default": "mlil" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "get_ssa_form",
                            "description": "Enumerate SSA variables (name and version) used in the function at the given address.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "rewrite_il",
                            "description": "Propose a local variable type for GUI approval.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "function": { "type": "number" },
                                    "variable": { "type": "string" },
                                    "type": { "type": "string" }
                                },
                                "required": ["function", "variable", "type"]
                            }
                        },
                        {
                            "name": "get_variable_uses",
                            "description": "Report every instruction address that reads or writes the named SSA variable in a function.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" },
                                    "variable": { "type": "string" },
                                    "version": { "type": "number" }
                                },
                                "required": ["address", "variable"]
                            }
                        },
                        {
                            "name": "diff_against_source",
                            "description": "Recompile the decompiled C for a function with the system C compiler and compare instruction-category histograms against the original.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": { "type": "number" }
                                },
                                "required": ["address"]
                            }
                        },
                        {
                            "name": "merge_jsonl_3way",
                            "description": "Three-way merge of three JSONL project exports. Returns merged text plus conflict stats. Used for git-friendly async collab.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "base": { "type": "string" },
                                    "left": { "type": "string" },
                                    "right": { "type": "string" }
                                },
                                "required": ["base", "left", "right"]
                            }
                        }
                    ]
                }
            }),

            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                self.call_tool(name, args, id)
            }

            // --- Resource Management ---
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resources": [
                        { "uri": "sleuthre://project/functions", "name": "Function List", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/strings", "name": "Extracted Strings", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/xrefs", "name": "Cross References", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/comments", "name": "User Comments", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/imports", "name": "Imported Functions", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/exports", "name": "Exported Functions", "mimeType": "application/json" },
                        { "uri": "sleuthre://project/bookmarks", "name": "Bookmarks", "mimeType": "application/json" }
                    ]
                }
            }),

            "resources/read" => {
                let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                self.read_resource(uri, id)
            }

            "notifications/initialized" => Value::Null, // Ignore
            _ => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("Method not found: {}", method) } })
            }
        }
    }

    fn call_tool(&mut self, name: &str, args: Value, id: Value) -> Value {
        match name {
            "open_binary" => {
                let Some(path) = args.get("path").and_then(|p| p.as_str()) else {
                    return missing_param_error(&id, "path");
                };
                let path = PathBuf::from(path);
                let raw = match args.get("raw").map(RawMapping::parse).transpose() {
                    Ok(mapping) => mapping,
                    Err(e) => {
                        return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":format!("Invalid raw mapping: {e}")}});
                    }
                };
                let analysis = analyze_file_with_triage(
                    &path,
                    AnalysisMode::Normal,
                    None,
                    |_| {},
                    |bytes| match &raw {
                        Some(mapping) => loader::load_raw_regions(
                            bytes,
                            &mapping.regions,
                            mapping.arch,
                            mapping
                                .byte_order
                                .unwrap_or_else(|| mapping.arch.default_endianness()),
                            mapping.entry_point,
                        ),
                        None => loader::load_binary_from_bytes(bytes),
                    },
                );
                match analysis {
                    Ok((mut result, report)) => {
                        result.project.triage_report = Some(report.into());
                        self.disasm = result.project.disassembler().ok();
                        self.project = Some(result.project);
                        tool_text_result(&id, "Binary loaded successfully")
                    }
                    Err(e) => {
                        let code = if raw.is_some() && matches!(e, re_core::error::Error::Loader(_))
                        {
                            -32602
                        } else {
                            -32001
                        };
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": e.to_string() } })
                    }
                }
            }
            "get_triage_report" => {
                let Some(params) = args.as_object().filter(|p| p.keys().all(|k| k == "format"))
                else {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Only the optional format parameter is supported"}});
                };
                let format = match params.get("format") {
                    None => ReportFormat::Json,
                    Some(value) => match value.as_str().and_then(|s| s.parse().ok()) {
                        Some(format) => format,
                        None => {
                            return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Expected json or markdown"}});
                        }
                    },
                };
                let Some(report) = self
                    .project
                    .as_ref()
                    .and_then(|p| p.triage_report.as_deref())
                else {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Open a binary to get its triage report"}});
                };
                let mut buffer = ReportBuffer(Vec::new());
                match report.write(format, &mut buffer) {
                    Ok(()) => tool_text_result(
                        &id,
                        std::str::from_utf8(&buffer.0).expect("report writers emit UTF-8"),
                    ),
                    Err(e) => {
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32002,"message":e.to_string()}})
                    }
                }
            }
            "get_disasm" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(10) as usize;
                if count > MAX_DISASM_COUNT {
                    return json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": format!("count exceeds maximum {}", MAX_DISASM_COUNT)
                        }
                    });
                }
                let Some(byte_limit) = count.checked_mul(15) else {
                    return json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32602, "message": "count is too large" }
                    });
                };
                if let (Some(project), Some(disasm)) = (&self.project, &self.disasm) {
                    let size = project
                        .memory_map
                        .segment_at(addr)
                        .map_or(byte_limit, |segment| {
                            let remaining = segment.size - (addr - segment.start);
                            remaining.min(byte_limit as u64) as usize
                        });
                    match disasm.disassemble_range(&project.memory_map, addr, size) {
                        Ok(insns) => {
                            let result: Vec<_> = insns.into_iter().take(count).collect();
                            tool_result(&id, &result)
                        }
                        Err(e) => {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } })
                        }
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "submit_rename" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let Some(name) = args
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
                else {
                    return missing_param_error(&id, "name");
                };
                let rationale = args
                    .get("rationale")
                    .and_then(|r| r.as_str())
                    .unwrap_or("AI Suggestion")
                    .to_string();
                if let Some(project) = &mut self.project {
                    let Some(func) = project.functions.get_function(addr) else {
                        return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32004,"message":"Unknown function"}});
                    };
                    let kind = ActionKind::Rename {
                        address: addr,
                        new_name: name,
                        old_name: func.name.clone(),
                    };
                    propose(project, kind, rationale, &id)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_xrefs" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let direction = args
                    .get("direction")
                    .and_then(|d| d.as_str())
                    .unwrap_or("both");
                if let Some(project) = &self.project {
                    let mut result = Vec::new();
                    if (direction == "to" || direction == "both")
                        && let Some(xrefs) = project.xrefs.to_address_xrefs.get(&addr)
                    {
                        for xref in xrefs {
                            result.push(json!({
                                "from": format!("0x{:x}", xref.from_address),
                                "to": format!("0x{:x}", xref.to_address),
                                "type": format!("{:?}", xref.xref_type),
                                "direction": "to"
                            }));
                        }
                    }
                    if (direction == "from" || direction == "both")
                        && let Some(xrefs) = project.xrefs.from_address_xrefs.get(&addr)
                    {
                        for xref in xrefs {
                            result.push(json!({
                                "from": format!("0x{:x}", xref.from_address),
                                "to": format!("0x{:x}", xref.to_address),
                                "type": format!("{:?}", xref.xref_type),
                                "direction": "from"
                            }));
                        }
                    }
                    tool_result(&id, &result)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "add_comment" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let Some(text) = args
                    .get("text")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
                else {
                    return missing_param_error(&id, "text");
                };
                if let Some(project) = &mut self.project {
                    propose(
                        project,
                        ActionKind::Comment {
                            address: addr,
                            new_comment: text,
                        },
                        "MCP comment proposal".into(),
                        &id,
                    )
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_strings" => {
                let filter = args.get("filter").and_then(|f| f.as_str()).unwrap_or("");
                let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(100) as usize;
                if let Some(project) = &self.project {
                    let strings: Vec<_> = project
                        .strings
                        .strings
                        .iter()
                        .filter(|s| filter.is_empty() || s.value.contains(filter))
                        .take(limit)
                        .collect();
                    tool_result(&id, &strings)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_cfg" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                if let (Some(project), Some(disasm)) = (&self.project, &self.disasm) {
                    let mut cfg = ControlFlowGraph::new();
                    match cfg.build_for_function(&project.memory_map, disasm, addr) {
                        Ok(()) => {
                            let blocks: Vec<_> = cfg
                                .graph
                                .node_indices()
                                .map(|idx| {
                                    let block = &cfg.graph[idx];
                                    json!({
                                        "start": format!("0x{:x}", block.start_address),
                                        "end": format!("0x{:x}", block.end_address),
                                        "instruction_count": block.instructions.len()
                                    })
                                })
                                .collect();
                            tool_result(
                                &id,
                                &json!({"blocks": blocks, "edge_count": cfg.graph.edge_count()}),
                            )
                        }
                        Err(e) => {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } })
                        }
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "save_project" => {
                let Some(path) = args.get("path").and_then(|p| p.as_str()) else {
                    return missing_param_error(&id, "path");
                };
                if let Some(project) = &mut self.project {
                    let resolved = match confine_save_path(
                        std::path::Path::new(path),
                        &project.path,
                    ) {
                        Ok(p) => p,
                        Err(msg) => {
                            return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": msg } });
                        }
                    };
                    let saved = if project.db.as_ref().is_some_and(|db| db.path() == resolved) {
                        project.save(&resolved)
                    } else {
                        project.save_new(&resolved)
                    };
                    match saved {
                        Ok(()) => tool_text_result(
                            &id,
                            &format!("Project saved to {}", resolved.display()),
                        ),
                        Err(e) => {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32003, "message": e.to_string() } })
                        }
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_decompilation" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let (Some(project), Some(disasm)) = (&mut self.project, &self.disasm) else {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"No project loaded"}});
                };
                if project.functions.get_function(addr).is_none() {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32004,"message":format!("No function found at address {addr:#x}")}});
                }
                match project.decompile_at(disasm, addr) {
                    Ok(code) => tool_text_result(&id, &code.text),
                    Err(e) => {
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32002,"message":e.to_string()}})
                    }
                }
            }
            "search_memory" => {
                let Some(pattern_str) = args.get("pattern").and_then(|p| p.as_str()) else {
                    return missing_param_error(&id, "pattern");
                };
                let limit = match args.get("limit") {
                    None => 50,
                    Some(value) => match value.as_u64() {
                        Some(n) if n <= MAX_SEARCH_RESULTS => n as usize,
                        _ => {
                            return json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32602, "message":"limit must be an integer from 0 to 1000"}});
                        }
                    },
                };
                if let Some(project) = &self.project {
                    let mut pattern: Vec<Option<u8>> = Vec::new();
                    for tok in pattern_str.split_whitespace() {
                        if tok == "??" {
                            pattern.push(None);
                        } else {
                            match u8::from_str_radix(tok, 16) {
                                Ok(byte) => pattern.push(Some(byte)),
                                Err(_) => {
                                    return json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": { "code": -32602, "message": format!("Invalid hex byte in pattern: '{}'", tok) }
                                    });
                                }
                            }
                        }
                    }
                    let results: Vec<String> = project
                        .memory_map
                        .search_bytes_limited(&pattern, limit)
                        .into_iter()
                        .map(|addr| format!("0x{:x}", addr))
                        .collect();
                    tool_result(&id, &results)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_imports" => {
                let filter = args.get("filter").and_then(|f| f.as_str()).unwrap_or("");
                if let Some(project) = &self.project {
                    let imports: Vec<_> = project
                        .imports
                        .iter()
                        .filter(|imp| filter.is_empty() || imp.name.contains(filter))
                        .collect();
                    tool_result(&id, &imports)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_exports" => {
                let filter = args.get("filter").and_then(|f| f.as_str()).unwrap_or("");
                if let Some(project) = &self.project {
                    let exports: Vec<_> = project
                        .exports
                        .iter()
                        .filter(|exp| filter.is_empty() || exp.name.contains(filter))
                        .collect();
                    tool_result(&id, &exports)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "detect_patterns" => {
                if let Some(project) = &mut self.project {
                    let sig_db = SignatureDatabase::builtin_x86_64();
                    let matches =
                        sig_db.scan_and_apply(&project.memory_map, &mut project.functions);
                    let result: Vec<_> = matches
                        .iter()
                        .map(|m| {
                            json!({
                                "address": format!("0x{:x}", m.address),
                                "name": m.signature_name,
                                "library": m.library
                            })
                        })
                        .collect();
                    tool_result(&id, &result)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "run_analysis_passes" => {
                if let Some(project) = &mut self.project {
                    let mut pm = re_core::plugin::PluginManager::default();
                    pm.register_analysis_pass(Box::new(
                        re_core::analysis::passes::SuspiciousNamePass,
                    ));

                    match pm.run_all_analysis_passes(
                        &project.memory_map,
                        &mut project.functions,
                        &project.xrefs,
                        &project.strings,
                    ) {
                        Ok(findings) => {
                            let result: Vec<_> = findings
                                .iter()
                                .map(|f| {
                                    json!({
                                        "address": format!("0x{:x}", f.address),
                                        "category": format!("{:?}", f.category),
                                        "message": f.message,
                                        "severity": f.severity
                                    })
                                })
                                .collect();
                            tool_result(&id, &result)
                        }
                        Err(e) => {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32006, "message": e.to_string() } })
                        }
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_bookmarks" => {
                if let Some(project) = &self.project {
                    let bookmarks: Vec<_> = project
                        .bookmarks
                        .iter()
                        .map(|(addr, note)| {
                            json!({ "address": format!("0x{:x}", addr), "note": note })
                        })
                        .collect();
                    tool_result(&id, &bookmarks)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "add_bookmark" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let note = args
                    .get("note")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(project) = &mut self.project {
                    project.bookmarks.insert(addr, note);
                    tool_text_result(&id, &format!("Bookmark added at 0x{:x}", addr))
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_function_signature" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                if let Some(project) = &self.project {
                    if let Some(sig) = project.types.function_signatures.get(&addr) {
                        tool_result(&id, sig)
                    } else {
                        tool_text_result(&id, &format!("No signature found for 0x{:x}", addr))
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "load_pdb" => {
                let Some(path) = args.get("path").and_then(|p| p.as_str()) else {
                    return missing_param_error(&id, "path");
                };
                if let Some(project) = &mut self.project {
                    let pdb_path = std::path::Path::new(path);
                    match debuginfo::extract_pdb_info(pdb_path, project.arch, project.image_base) {
                        Ok(debug_info) => {
                            let mut sig_count = 0usize;
                            let mut type_count = 0usize;
                            for ty in &debug_info.types {
                                project.types.add_type(ty.clone());
                                type_count += 1;
                            }
                            for (&addr, sig) in &debug_info.function_signatures {
                                project.types.function_signatures.insert(addr, sig.clone());
                                sig_count += 1;
                                if let Some(func) = project.functions.functions.get_mut(&addr)
                                    && func.name.starts_with("sub_")
                                {
                                    func.name.clone_from(&sig.name);
                                }
                            }
                            for (&addr, var) in &debug_info.global_variables {
                                project.types.global_variables.insert(addr, var.clone());
                            }
                            for (&addr, vars) in &debug_info.local_variables {
                                project.types.local_variables.insert(addr, vars.clone());
                            }
                            tool_text_result(
                                &id,
                                &format!(
                                    "PDB loaded: {} signatures, {} types",
                                    sig_count, type_count
                                ),
                            )
                        }
                        Err(e) => {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32005, "message": e.to_string() } })
                        }
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_source_line" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                if let Some(project) = &self.project {
                    if let Some(info) = project.types.source_lines.get(&addr) {
                        tool_result(&id, info)
                    } else {
                        tool_text_result(&id, &format!("No source line info for 0x{:x}", addr))
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "get_microcode" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let tier = args
                    .get("tier")
                    .and_then(|t| t.as_str())
                    .unwrap_or("mlil")
                    .to_ascii_lowercase();
                let (Some(project), Some(disasm)) = (&self.project, &self.disasm) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } });
                };
                let Some(func) = project.functions.get_function(addr) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32004, "message": format!("No function at 0x{:x}", addr) } });
                };
                let size = func
                    .end_address
                    .and_then(|end| end.checked_sub(func.start_address))
                    .map(|s| s as usize)
                    .unwrap_or(0x100);
                let instructions = match disasm.disassemble_range(
                    &project.memory_map,
                    func.start_address,
                    size,
                ) {
                    Ok(insns) => insns,
                    Err(e) => {
                        return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } });
                    }
                };
                let llil = re_core::il::lift_function(
                    disasm.arch,
                    &func.name,
                    func.start_address,
                    &instructions,
                );
                let text = if tier == "llil" {
                    format_llil(&llil)
                } else {
                    let mlil = re_core::il::mlil::lower_to_mlil(&llil);
                    format_mlil(&mlil)
                };
                tool_text_result(&id, &text)
            }
            "get_ssa_form" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let (Some(project), Some(disasm)) = (&self.project, &self.disasm) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } });
                };
                let Some(func) = project.functions.get_function(addr) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32004, "message": format!("No function at 0x{:x}", addr) } });
                };
                let size = func
                    .end_address
                    .and_then(|end| end.checked_sub(func.start_address))
                    .map(|s| s as usize)
                    .unwrap_or(0x100);
                let instructions = match disasm.disassemble_range(
                    &project.memory_map,
                    func.start_address,
                    size,
                ) {
                    Ok(insns) => insns,
                    Err(e) => {
                        return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } });
                    }
                };
                let llil = re_core::il::lift_function(
                    disasm.arch,
                    &func.name,
                    func.start_address,
                    &instructions,
                );
                let mlil = re_core::il::mlil::lower_to_mlil(&llil);
                let ssa_vars = collect_ssa_vars(&mlil);
                tool_result(&id, &ssa_vars)
            }
            "rewrite_il" => {
                let Some(func_addr) = args.get("function").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "function");
                };
                let Some(var_name) = args.get("variable").and_then(|v| v.as_str()) else {
                    return missing_param_error(&id, "variable");
                };
                let Some(type_str) = args.get("type").and_then(|t| t.as_str()) else {
                    return missing_param_error(&id, "type");
                };
                let Some(project) = &mut self.project else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } });
                };
                if project.functions.get_function(func_addr).is_none()
                    || type_str.len() > 256
                    || type_str.trim().is_empty()
                    || var_name.is_empty()
                {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Invalid function, variable or type"}});
                }
                propose(
                    project,
                    ActionKind::SetLocalType {
                        function: func_addr,
                        variable: var_name.into(),
                        type_name: type_str.into(),
                    },
                    "MCP local type proposal".into(),
                    &id,
                )
            }
            "get_variable_uses" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let Some(var_name) = args.get("variable").and_then(|v| v.as_str()) else {
                    return missing_param_error(&id, "variable");
                };
                let version = args
                    .get("version")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let (Some(project), Some(disasm)) = (&self.project, &self.disasm) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } });
                };
                let Some(func) = project.functions.get_function(addr) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32004, "message": format!("No function at 0x{:x}", addr) } });
                };
                let size = func
                    .end_address
                    .and_then(|end| end.checked_sub(func.start_address))
                    .map(|s| s as usize)
                    .unwrap_or(0x100);
                let instructions = match disasm.disassemble_range(
                    &project.memory_map,
                    func.start_address,
                    size,
                ) {
                    Ok(insns) => insns,
                    Err(e) => {
                        return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } });
                    }
                };
                let llil = re_core::il::lift_function(
                    disasm.arch,
                    &func.name,
                    func.start_address,
                    &instructions,
                );
                let mlil = re_core::il::mlil::lower_to_mlil(&llil);
                let all = collect_ssa_vars(&mlil);
                let filtered: Vec<_> = all
                    .into_iter()
                    .filter(|v| {
                        let name_match = v
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n == var_name)
                            .unwrap_or(false);
                        let ver_match = match version {
                            Some(want) => v
                                .get("version")
                                .and_then(|n| n.as_u64())
                                .map(|n| n as u32 == want)
                                .unwrap_or(false),
                            None => true,
                        };
                        name_match && ver_match
                    })
                    .collect();
                tool_result(&id, &filtered)
            }
            "diff_against_source" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let (Some(project), Some(disasm)) = (&self.project, &self.disasm) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } });
                };
                let Some(func) = project.functions.get_function(addr) else {
                    return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32004, "message": format!("No function at 0x{:x}", addr) } });
                };
                let original = match project.function_instructions(disasm, addr) {
                    Ok(insns) => insns,
                    Err(e) => {
                        return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } });
                    }
                };
                let pseudocode = project.decompile_instructions(addr, &original);
                match re_core::analysis::recompile_diff::recompile_and_diff(
                    &func.name,
                    &pseudocode.text,
                    &original,
                    disasm.arch,
                ) {
                    Ok(result) => tool_result(&id, &result),
                    Err(e) => {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32003, "message": e.to_string() } })
                    }
                }
            }
            "merge_jsonl_3way" => {
                let Some(base) = args.get("base").and_then(|v| v.as_str()) else {
                    return missing_param_error(&id, "base");
                };
                let Some(left) = args.get("left").and_then(|v| v.as_str()) else {
                    return missing_param_error(&id, "left");
                };
                let Some(right) = args.get("right").and_then(|v| v.as_str()) else {
                    return missing_param_error(&id, "right");
                };
                match re_core::project::merge_jsonl_3way(base, left, right) {
                    Ok(result) => tool_result(
                        &id,
                        &json!({
                            "merged": result.merged,
                            "conflicts": result.conflict_count,
                            "left_adds": result.left_adds,
                            "right_adds": result.right_adds,
                            "shared_changes": result.shared_changes,
                        }),
                    ),
                    Err(e) => {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32603, "message": e.to_string() } })
                    }
                }
            }
            _ => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Tool not found" } })
            }
        }
    }

    fn read_resource(&self, uri: &str, id: Value) -> Value {
        match uri {
            "sleuthre://project/functions" => {
                if let Some(project) = &self.project {
                    let funcs: Vec<_> = project.functions.functions.values().collect();
                    resource_result(&id, uri, &funcs)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/strings" => {
                if let Some(project) = &self.project {
                    resource_result(&id, uri, &project.strings.strings)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/xrefs" => {
                if let Some(project) = &self.project {
                    let all_xrefs: Vec<_> =
                        project.xrefs.to_address_xrefs.values().flatten().collect();
                    resource_result(&id, uri, &all_xrefs)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/comments" => {
                if let Some(project) = &self.project {
                    resource_result(&id, uri, &project.comments)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/imports" => {
                if let Some(project) = &self.project {
                    resource_result(&id, uri, &project.imports)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/exports" => {
                if let Some(project) = &self.project {
                    resource_result(&id, uri, &project.exports)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "sleuthre://project/bookmarks" => {
                if let Some(project) = &self.project {
                    let bookmarks: Vec<_> = project
                        .bookmarks
                        .iter()
                        .map(|(addr, note)| {
                            json!({ "address": format!("0x{:x}", addr), "note": note })
                        })
                        .collect();
                    resource_result(&id, uri, &bookmarks)
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            _ => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Resource not found" } })
            }
        }
    }
}

fn main() -> Result<()> {
    let mut server = McpServer::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("failed to read request line from stdin")?;
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => {
                let response = server.handle_request(request);
                if response != Value::Null {
                    let text =
                        serde_json::to_string(&response).context("failed to serialize response")?;
                    println!("{}", text);
                }
            }
            Err(e) => {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                });
                let text = serde_json::to_string(&error_response)
                    .context("failed to serialize error response")?;
                println!("{}", text);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use re_core::analysis::triage::TriageReport;

    #[test]
    fn initialize_returns_protocol_version() {
        let mut server = McpServer::new();
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let resp = server.handle_request(req);
        let version = resp["result"]["protocolVersion"].as_str().unwrap();
        assert_eq!(version, "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "sleuthre-core");
    }

    #[test]
    fn tools_list_returns_tools() {
        let mut server = McpServer::new();
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let resp = server.handle_request(req);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"open_binary"));
        assert!(names.contains(&"get_triage_report"));
        assert!(names.contains(&"get_disasm"));
        assert!(names.contains(&"get_xrefs"));
    }

    #[test]
    fn triage_tool_exports_the_open_sample_and_rejects_invalid_requests() {
        let mut server = McpServer::new();
        let mut call = |name, args| {
            server.handle_request(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": name, "arguments": args }
            }))
        };
        assert_eq!(
            call("get_triage_report", json!({}))["error"]["code"],
            -32000
        );
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../re-core/tests/fixtures/triage.pe");
        assert!(
            call("open_binary", json!({"path": fixture}))
                .get("result")
                .is_some()
        );
        for (args, extension) in [(json!({}), "json"), (json!({"format": "markdown"}), "md")] {
            let response = call("get_triage_report", args);
            assert_eq!(
                response["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
                std::fs::read(fixture.with_extension(extension)).unwrap()
            );
        }
        for args in [
            json!({"format": 1}),
            json!({"format": "xml"}),
            json!({"path": "other"}),
        ] {
            assert_eq!(call("get_triage_report", args)["error"]["code"], -32602);
        }
    }

    #[test]
    fn raw_open_matches_the_shared_report_and_preserves_it_on_overlap() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../re-core/tests/fixtures/two-regions.raw");
        let mut server = McpServer::new();
        let mut call = |name, args| {
            server.handle_request(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": name, "arguments": args }
            }))
        };
        let mut args = json!({
            "path": fixture,
            "raw": {
                "arch": "mips", "byte_order": "little", "entry_point": 32769,
                "regions": [
                    {"name": "high", "file_offset": 4, "length": 4, "start": 32768},
                    {"name": "low", "file_offset": 0, "length": 4, "start": 4096}
                ]
            }
        });
        assert!(call("open_binary", args.clone())["result"].is_object());
        let before = call("get_triage_report", json!({}));
        assert_eq!(
            before["result"]["content"][0]["text"].as_str().unwrap(),
            include_str!("../../re-core/tests/fixtures/two-regions.json")
        );

        args["raw"]["regions"][0]["start"] = json!(4098);
        let error = call("open_binary", args);
        assert_eq!(error["error"]["code"], -32602);
        let message = error["error"]["message"].as_str().unwrap();
        assert!(
            ["high", "low", "overlaps"]
                .iter()
                .all(|word| message.contains(word)),
            "{message}"
        );
        assert_eq!(call("get_triage_report", json!({})), before);
        for (pattern, addresses) in [
            ("42", "[\"0x1001\"]"),
            ("46", "[\"0x8001\"]"),
            ("44 45", "[]"),
        ] {
            let result = call("search_memory", json!({"pattern":pattern}));
            assert_eq!(result["result"]["content"][0]["text"], addresses);
        }
    }

    #[test]
    fn raw_open_uses_architecture_and_first_region_defaults() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../re-core/tests/fixtures/mips-addiu.raw");
        let mut server = McpServer::new();
        let opened = server.call_tool(
            "open_binary",
            json!({
                "path": fixture, "raw": { "arch": "mips", "regions": [
                    {"name": "code", "file_offset": 4, "length": 4, "start": 32768},
                    {"name": "low", "file_offset": 0, "length": 4, "start": 4096}
                ]}
            }),
            json!(1),
        );
        assert!(opened["result"].is_object(), "{opened}");
        let project = server.project.as_ref().unwrap();
        let report = project.triage_report.as_ref().unwrap();
        assert_eq!(report.byte_order, Some(Endianness::Big));
        assert_eq!(report.entry_point.0, 0x8000);
        let response = server.call_tool("get_disasm", json!({"address":32768,"count":1}), json!(2));
        let listing: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(listing[0]["mnemonic"], "addiu");
    }

    #[test]
    fn malformed_raw_options_fail_before_file_io() {
        let mut server = McpServer::new();
        let region = json!({"name":"low","file_offset":0,"length":4,"start":4096});
        for raw in [
            Value::Null,
            json!({"arch":"mips", "regions":[]}),
            json!({"arch":"unknown", "regions":[region]}),
            json!({"arch":"mips", "byte_order":"middle", "regions":[region]}),
            json!({"arch":"mips", "regions":[region], "typo":1}),
            json!({"arch":"mips", "regions":[{"name":" ","length":4,"file_offset":0,"start":0}]}),
            json!({"arch":"mips", "regions":[{"name":"low","length":4,"file_offset":-1,"start":0}]}),
            json!({"arch":"mips", "regions":[["low", 0, 4, 4096]]}),
        ] {
            let response = server.call_tool(
                "open_binary",
                json!({"path":"missing-image","raw":raw}),
                json!(1),
            );
            assert_eq!(response["error"]["code"], -32602, "{raw}: {response}");
        }
    }

    #[test]
    fn oversized_triage_tool_result_returns_an_error_without_partial_content() {
        let mut server = McpServer::new();
        let mut report =
            TriageReport::from_bytes(include_bytes!("../../re-core/tests/fixtures/triage.pe"))
                .unwrap();
        report.imports[0].name = "a".repeat(MAX_TRIAGE_BYTES);
        let mut project = Project::new("fixture".into(), PathBuf::new());
        project.triage_report = Some(report.into());
        server.project = Some(project);
        let response = server.call_tool("get_triage_report", json!({}), json!(1));
        assert_eq!(response["error"]["code"], -32002);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("8 MiB")
        );
        assert!(response.get("result").is_none());
    }

    #[test]
    fn proposals_survive_handoff_and_stale_saves_cannot_revert_review() {
        use re_core::analysis::functions::{CallingConvention, Function};
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        {
            let mut server = McpServer::new();
            let mut project = Project::new("sample".into(), dir.join("sample.exe"));
            project.functions.add_function(Function {
                start_address: 16,
                end_address: None,
                name: "entry".into(),
                calling_convention: CallingConvention::default(),
                stack_frame_size: 0,
            });
            server.project = Some(project);
            let save = json!({"path":"handoff.slre"});
            for (name, args) in [
                ("submit_rename", json!({"address":16,"name":"main"})),
                ("add_comment", json!({"address":16,"text":"reviewed"})),
                (
                    "rewrite_il",
                    json!({"function":16,"variable":"v","type":"int"}),
                ),
                ("add_comment", json!({"address":17,"text":"reject this"})),
                ("save_project", save.clone()),
            ] {
                let response = server.call_tool(name, args, json!(1));
                assert!(response["error"].is_null(), "{response}");
            }
            let path = dir.join("handoff.slre");
            let mut reviewer = Project::load(&path).unwrap();
            assert_eq!(reviewer.functions.functions[&16].name, "entry");
            assert!(reviewer.comments.is_empty());
            assert!(reviewer.types.local_variables.is_empty());
            assert_eq!(reviewer.pending_actions.len(), 4);
            for _ in 0..3 {
                reviewer
                    .approve_action(reviewer.pending_actions[0].id)
                    .unwrap();
            }
            reviewer.pending_actions.clear(); // reject remaining proposal
            assert_eq!(
                reviewer.types.local_variables[&16][0]
                    .type_ref
                    .display_name(),
                "int32_t"
            );
            reviewer.autosave().unwrap();
            assert!(server.call_tool("save_project", save, json!(2))["error"].is_object());
            let saved = Project::load(&path).unwrap();
            assert!(saved.pending_actions.is_empty());
            assert_eq!(saved.functions.functions[&16].name, "main");
            assert_eq!(saved.comments[&16], "reviewed");
            assert!(!saved.comments.contains_key(&17));
            assert_eq!(saved.types.local_variables[&16].len(), 1);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn search_rejects_limits_outside_the_advertised_range() {
        let mut server = McpServer::new();
        for limit in [json!(1001), json!(-1), json!(0.5)] {
            let response = server.call_tool(
                "search_memory",
                json!({"limit":limit,"pattern":"00"}),
                json!(1),
            );
            assert_eq!(response["error"]["code"], -32602);
        }
    }

    #[test]
    fn unknown_method_returns_error() {
        let mut server = McpServer::new();
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "nonexistent"});
        let resp = server.handle_request(req);
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn tool_call_without_project_returns_error() {
        let mut server = McpServer::new();
        let req = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "get_disasm", "arguments": {"address": 0}}
        });
        let resp = server.handle_request(req);
        assert!(resp["error"].is_object(), "Expected error response");
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.to_lowercase().contains("no project"),
            "Expected 'no project' error, got: {}",
            msg
        );
    }

    #[test]
    fn get_disasm_rejects_excessive_count() {
        let mut server = McpServer::new();
        let req = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_disasm",
                "arguments": { "address": 0, "count": (MAX_DISASM_COUNT as u64) + 1 }
            }
        });
        let resp = server.handle_request(req);
        assert_eq!(resp["error"]["code"], -32602);
        let msg = resp["error"]["message"].as_str().unwrap();
        assert!(msg.contains("count exceeds maximum"));
    }

    #[test]
    fn helper_tool_text_result_format() {
        let id = json!(42);
        let resp = tool_text_result(&id, "hello");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["content"][0]["text"], "hello");
    }

    #[test]
    fn confine_save_path_enforces_workspace_and_extension() {
        let workspace = std::env::temp_dir().join(format!("slre-mcp-test-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let binary = workspace.join("sample.exe");

        // A bare file name lands inside the workspace.
        let ok = confine_save_path(std::path::Path::new("out.slre"), &binary).unwrap();
        assert_eq!(ok.parent().unwrap(), workspace.canonicalize().unwrap());

        // Wrong extension, absolute escape, and `..` traversal are rejected.
        assert!(confine_save_path(std::path::Path::new("out.txt"), &binary).is_err());
        assert!(confine_save_path(std::path::Path::new("/etc/pwned.slre"), &binary).is_err());
        assert!(confine_save_path(std::path::Path::new("../escape.slre"), &binary).is_err());

        std::fs::remove_dir_all(&workspace).ok();
    }

    #[test]
    fn helper_missing_param_error_format() {
        let id = json!(1);
        let resp = missing_param_error(&id, "path");
        assert_eq!(resp["error"]["code"], -32602);
        let msg = resp["error"]["message"].as_str().unwrap();
        assert!(msg.contains("path"));
    }
}
