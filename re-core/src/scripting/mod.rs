use crate::project::Project;
use rhai::{Engine, EvalAltResult, Scope};

pub struct ScriptEngine {
    engine: Engine,
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptEngine {
    pub fn new() -> Self {
        let engine = Engine::new();
        // Project cannot be registered directly because it is not Clone.
        // We need a proxy object or architectural change to support scripting fully.
        Self { engine }
    }

    pub fn eval(
        &self,
        script: &str,
        _project: &mut Project,
    ) -> Result<rhai::Dynamic, Box<EvalAltResult>> {
        let mut scope = Scope::new();
        self.engine.eval_with_scope(&mut scope, script)
    }
}
