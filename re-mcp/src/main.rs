use anyhow::Result;
use re_core::analysis::cfg::ControlFlowGraph;
use re_core::analysis::type_propagation::FunctionTypeInfo;
use re_core::debuginfo;
use re_core::disasm::Disassembler;
use re_core::il::structuring::decompile;
use re_core::project::{ActionKind, PendingAction, Project};
use re_core::signatures::SignatureDatabase;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;
use uuid::Uuid;

struct McpServer {
    project: Option<Project>,
    disasm: Option<Disassembler>,
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
                    "serverInfo": { "name": "sleuthre-core", "version": "0.1.0" }
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
                            "description": "Load a binary file (ELF/PE) for analysis",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "path": { "type": "string" } },
                                "required": ["path"]
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
                            "description": "Add a comment at an address",
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
                                    "limit": { "type": "number" }
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
                match re_core::analysis::pipeline::analyze_binary(&path, |_| {}) {
                    Ok(result) => {
                        self.disasm = Disassembler::new(result.project.arch).ok();
                        self.project = Some(result.project);
                        tool_text_result(&id, "Binary loaded successfully")
                    }
                    Err(e) => {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": e.to_string() } })
                    }
                }
            }
            "get_disasm" => {
                let Some(addr) = args.get("address").and_then(|a| a.as_u64()) else {
                    return missing_param_error(&id, "address");
                };
                let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(10) as usize;
                if let (Some(project), Some(disasm)) = (&self.project, &self.disasm) {
                    match disasm.disassemble_range(&project.memory_map, addr, count * 15) {
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
                    let old_name = project
                        .functions
                        .get_function(addr)
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| format!("sub_{:X}", addr));
                    project.pending_actions.push(PendingAction {
                        id: Uuid::new_v4(),
                        kind: ActionKind::Rename {
                            address: addr,
                            new_name: name,
                            old_name,
                        },
                        rationale,
                        confidence: 0.9,
                    });
                    tool_text_result(&id, "Rename submitted for approval")
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
                    if text.is_empty() {
                        project.comments.remove(&addr);
                    } else {
                        project.comments.insert(addr, text.clone());
                    }
                    tool_text_result(&id, &format!("Comment set at 0x{:x}", addr))
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
                    match project.save(std::path::Path::new(path)) {
                        Ok(()) => tool_text_result(&id, &format!("Project saved to {}", path)),
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
                if let (Some(project), Some(disasm)) = (&self.project, &self.disasm) {
                    if let Some(func) = project.functions.get_function(addr) {
                        let size = func
                            .end_address
                            .and_then(|end| end.checked_sub(func.start_address))
                            .map(|s| s as usize)
                            .unwrap_or(0x100);
                        match disasm.disassemble_range(
                            &project.memory_map,
                            func.start_address,
                            size,
                        ) {
                            Ok(instructions) => {
                                let arch = self
                                    .disasm
                                    .as_ref()
                                    .map(|d| d.arch)
                                    .unwrap_or(re_core::arch::Architecture::X86_64);

                                let mut symbols = HashMap::new();
                                for f in project.functions.functions.values() {
                                    symbols.insert(f.start_address, f.name.clone());
                                }
                                for sym in &project.symbols {
                                    symbols.insert(sym.address, sym.name.clone());
                                }
                                for imp in &project.imports {
                                    symbols.insert(imp.address, imp.name.clone());
                                }

                                // Build type info
                                let type_info =
                                    project.types.function_signatures.get(&addr).map(|sig| {
                                        FunctionTypeInfo {
                                            signature: Some(sig.clone()),
                                            var_types: Default::default(),
                                        }
                                    });

                                let pseudocode = decompile(
                                    &func.name,
                                    &instructions,
                                    arch,
                                    &symbols,
                                    type_info.as_ref(),
                                    &project.types,
                                    &project.memory_map,
                                );
                                tool_text_result(&id, &pseudocode.text)
                            }
                            Err(e) => {
                                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": e.to_string() } })
                            }
                        }
                    } else {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32004, "message": format!("No function found at address 0x{:x}", addr) } })
                    }
                } else {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": "No project loaded" } })
                }
            }
            "search_memory" => {
                let Some(pattern_str) = args.get("pattern").and_then(|p| p.as_str()) else {
                    return missing_param_error(&id, "pattern");
                };
                let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize;
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
                        .search_bytes(&pattern)
                        .into_iter()
                        .take(limit)
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
                    match debuginfo::extract_pdb_info(pdb_path, project.arch) {
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
        let line = line?;
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => {
                let response = server.handle_request(request);
                if response != Value::Null {
                    println!("{}", serde_json::to_string(&response)?);
                }
            }
            Err(e) => {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                });
                println!("{}", serde_json::to_string(&error_response)?);
            }
        }
    }
    Ok(())
}
