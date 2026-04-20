// rename_alloc_funcs.rhai
//
// Example sleuthre plugin: scans the current project for functions whose
// current name contains "alloc" and annotates them with a clearer label.
// Demonstrates the iteration + rename pattern that most cleanup scripts need.
//
// Run via Tools > Plugins > Run: rename_alloc_funcs

let renamed = 0;
for f in functions {
    let lower = f.name.to_lower();
    if lower.contains("alloc") && !lower.starts_with("known_alloc_") {
        let new_name = `known_alloc_${f.address}`;
        rename(f.address, new_name);
        renamed += 1;
    }
}
println(`Renamed ${renamed} alloc-family functions.`);
