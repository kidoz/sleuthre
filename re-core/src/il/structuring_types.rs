fn get_expr_type(
    expr: &HlilExpr,
    inferred_types: &HashMap<String, TypeRef>,
    types: &TypeManager,
) -> Option<TypeRef> {
    match expr {
        HlilExpr::Const(_) => Some(TypeRef::Primitive(PrimitiveType::U64)),
        HlilExpr::Var(name) => inferred_types.get(name).cloned(),
        HlilExpr::Global(addr, _) => {
             if let Some(var) = types.global_variables.get(addr) {
                 Some(var.type_ref.clone())
             } else {
                 None
             }
        }
        HlilExpr::Call { target, .. } => {
             if let HlilExpr::Global(addr, _) = &**target {
                 types.function_signatures.get(addr).map(|s| s.return_type.clone())
             } else if let HlilExpr::Var(name) = &**target {
                 // Check if variable is function pointer
                 if let Some(TypeRef::FunctionPointer { return_type, .. }) = inferred_types.get(name) {
                     Some(*return_type.clone())
                 } else {
                     None
                 }
             } else {
                 None
             }
        }
        HlilExpr::Deref { size, .. } => {
             Some(TypeRef::Primitive(match size {
                 1 => PrimitiveType::U8,
                 2 => PrimitiveType::U16,
                 4 => PrimitiveType::U32,
                 8 => PrimitiveType::U64,
                 _ => PrimitiveType::Void,
             }))
        }
        HlilExpr::FieldAccess { base, field_name, is_ptr } => {
            let base_type = get_expr_type(base, inferred_types, types)?;
            let struct_type = if *is_ptr {
                if let TypeRef::Pointer(inner) = base_type { *inner } else { return None; }
            } else {
                base_type
            };
            
            if let TypeRef::Named(name) = struct_type {
                if let Some(crate::types::CompoundType::Struct { fields, .. } | crate::types::CompoundType::Union { fields, .. }) = types.get_type(&name) {
                    return fields.iter().find(|f| f.name == *field_name).map(|f| f.type_ref.clone());
                }
            }
            None
        }
        HlilExpr::ArrayAccess { base, .. } => {
            let base_type = get_expr_type(base, inferred_types, types)?;
            if let TypeRef::Array { element, .. } = base_type {
                Some(*element)
            } else if let TypeRef::Pointer(inner) = base_type {
                Some(*inner)
            } else {
                None
            }
        }
        _ => None,
    }
}
