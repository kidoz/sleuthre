// find_xor_loops.rhai
//
// Example sleuthre plugin: flags functions whose name hints at XOR-based
// crypto/obfuscation so the analyst can focus on likely-interesting code.
// Writes a comment tag on each match rather than renaming so the original
// name is preserved.

let flagged = 0;
for f in functions {
    let lower = f.name.to_lower();
    if lower.contains("xor") || lower.contains("crypt") || lower.contains("scramble") {
        set_comment(f.address, "// TODO: likely XOR/crypto routine — inspect loop body");
        flagged += 1;
    }
}
println(`Flagged ${flagged} candidate XOR/crypto routines.`);
