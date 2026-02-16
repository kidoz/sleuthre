fn recover_switch(target: &MlilExpr, memory: &crate::memory::MemoryMap) -> Option<HlilStmt> {
    // Pattern: Jump(Load(base + index * scale))
    if let MlilExpr::Load { addr, size } = target {
        if let MlilExpr::BinOp { op: crate::il::llil::BinOp::Add, left, right } = &**addr {
            let (base, offset) = if let MlilExpr::Const(c) = &**left {
                (*c, &**right)
            } else if let MlilExpr::Const(c) = &**right {
                (*c, &**left)
            } else {
                return None;
            };

            // Offset might be index * scale or just index (if scale is 1)
            let (index_expr, scale) = if let MlilExpr::BinOp { op: crate::il::llil::BinOp::Mul, left, right } = offset {
                if let MlilExpr::Const(s) = &**left {
                    (right, *s)
                } else if let MlilExpr::Const(s) = &**right {
                    (left, *s)
                } else {
                    (offset, 1)
                }
            } else {
                (offset, 1)
            };
            
            // Validate scale matches pointer size
            if scale != *size as u64 {
                return None;
            }

            // Heuristic: Read pointers from base until invalid
            let mut cases = Vec::new();
            let mut cursor = base;
            let mut idx = 0;
            // Limit to reasonable number of cases
            while cases.len() < 256 {
                let ptr = if *size == 8 {
                    match memory.read_u64(cursor) {
                        Ok(p) => p,
                        Err(_) => break,
                    }
                } else {
                    match memory.read_u32(cursor) {
                        Ok(p) => p as u64,
                        Err(_) => break,
                    }
                };
                
                // Validate pointer points to executable code
                if !memory.is_executable(ptr) {
                    break;
                }

                cases.push((idx, vec![HlilStmt::Goto(ptr)]));
                cursor += *size as u64;
                idx += 1;
            }

            if !cases.is_empty() {
                return Some(HlilStmt::Switch {
                    cond: hlil::mlil_to_hlil_expr(index_expr),
                    cases,
                    default: vec![], // Unknown default from just the jump
                });
            }
        }
    }
    None
}
