use super::Project;
use crate::analysis::type_propagation::FunctionTypeInfo;
use crate::disasm::{Disassembler, Instruction};
use crate::il::hlil::DecompiledCode;
use crate::{Error, Result};
use std::collections::HashMap;
use std::ops::Bound::{Excluded, Unbounded};

impl Project {
    /// Use the recorded function extent when available. For an unknown extent,
    /// stop at the next known start, the segment end, or the preview budget.
    pub fn function_instructions(
        &self,
        disasm: &Disassembler,
        address: u64,
    ) -> Result<Vec<Instruction>> {
        let segment = self
            .memory_map
            .segment_at(address)
            .ok_or_else(|| Error::Analysis(format!("Unmapped address {address:#x}")))?;
        let available = segment.size - (address - segment.start);
        let function = self.functions.get_function(address);
        let size = match function.and_then(|f| f.end_address) {
            Some(end) => end
                .checked_sub(address)
                .filter(|size| *size > 0)
                .ok_or_else(|| {
                    Error::Analysis(format!("Invalid function extent at {address:#x}"))
                })?,
            None => self
                .functions
                .functions
                .range((Excluded(address), Unbounded))
                .next()
                .map_or(256, |(&next, _)| (next - address).min(256)),
        }
        .min(available);
        if size > 0x10000 {
            return Err(Error::Analysis(format!(
                "Function at {address:#x} exceeds the 64 KiB decompilation limit"
            )));
        }
        disasm.disassemble_range(&self.memory_map, address, size as usize)
    }

    pub fn decompile_instructions(
        &self,
        address: u64,
        instructions: &[Instruction],
    ) -> DecompiledCode {
        let mut symbols = HashMap::new();
        for sym in &self.symbols {
            symbols.insert(sym.address, sym.name.clone());
        }
        for imp in &self.imports {
            symbols.insert(imp.address, imp.name.clone());
        }
        let mut conventions = HashMap::new();
        for func in self.functions.functions.values() {
            symbols.insert(func.start_address, func.name.clone());
            conventions.insert(func.start_address, func.calling_convention);
        }
        let name = self
            .functions
            .get_function(address)
            .map_or("sub_unknown", |f| f.name.as_str());
        let info = self
            .types
            .function_signatures
            .get(&address)
            .map(|signature| FunctionTypeInfo {
                signature: Some(signature.clone()),
                var_types: Default::default(),
            });
        crate::il::structuring::decompile(
            name,
            instructions,
            self.arch,
            &symbols,
            info.as_ref(),
            &self.types,
            &self.memory_map,
            &conventions,
        )
    }

    pub fn decompile_at(&mut self, disasm: &Disassembler, address: u64) -> Result<DecompiledCode> {
        let instructions = self.function_instructions(disasm, address)?;
        let code = self.decompile_instructions(address, &instructions);
        let (callees, types) = code.dependencies();
        self.cache_deps.set_dependencies(address, callees, types);
        self.decompilation_cache.insert(address, code.clone());
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::{CallingConvention, Function};
    use crate::memory::{MemorySegment, Permissions};
    use crate::types::{VariableInfo, VariableLocation, parse_type_str};

    #[test]
    fn function_extent_and_project_types_reach_the_decompiler() {
        let mut p = Project::new("sample".into(), "sample.exe".into());
        let mut bytes = vec![0x90; 510];
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        p.memory_map
            .add_segment(MemorySegment {
                name: "text".into(),
                start: 0x1000,
                size: bytes.len() as u64,
                data: bytes,
                permissions: Permissions::EXECUTE,
            })
            .unwrap();
        let disasm = Disassembler::new(p.arch).unwrap();
        for (address, end) in [(0x1000, Some(0x11fe)), (0x11fe, None)] {
            p.functions.add_function(Function {
                name: format!("sub_{address:x}"),
                start_address: address,
                end_address: end,
                calling_convention: CallingConvention::default(),
                stack_frame_size: 0,
            });
        }
        assert_eq!(p.function_instructions(&disasm, 0x1000).unwrap().len(), 510);
        assert_eq!(p.function_instructions(&disasm, 0x11fe).unwrap().len(), 2);
        p.types.local_variables.insert(
            0x11fe,
            vec![VariableInfo {
                name: "reviewed_local".into(),
                type_ref: parse_type_str("ReviewedType *"),
                location: VariableLocation::Register("eax".into()),
            }],
        );
        let code = p.decompile_at(&disasm, 0x11fe).unwrap();
        assert!(code.text.contains("ReviewedType"));
        assert!(code.text.contains("reviewed_local"));
    }
}
