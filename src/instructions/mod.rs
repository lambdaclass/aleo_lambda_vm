// Here we enforce to use the function from the module to avoid add::add-like
// usage to promote instructions::add-like usage.
mod add;
pub use add::add;

mod cast;
pub use cast::cast;

pub(crate) mod helpers;

mod is_eq;
pub use is_eq::is_eq;

mod mul;
pub use mul::mul;

mod sub;
pub use sub::sub;
