pub mod engine;
pub mod model;
pub mod path;

pub use engine::PolicyEngine;
pub use model::{resolve_resource_pattern, Policy, PolicyRule, RuleSpecificity};
pub use path::{is_path_resource, resolve_real_path, resolve_request_target};

#[cfg(feature = "test-hooks")]
pub use path::{
    clear_resolution_hook, reset_resolution_count, resolution_count, set_resolution_hook,
};
