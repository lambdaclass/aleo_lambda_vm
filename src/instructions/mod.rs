// Here we enforce to use the function from the module to avoid add::add-like
// usage to promote instructions::add-like usage.
mod add;
pub use add::add;

mod cast;
pub use cast::cast;

mod div;
pub use div::div;

mod hash_psd2;
pub use hash_psd2::hash_psd2;

pub(crate) mod helpers;

mod is_eq;
pub use is_eq::is_eq;

mod mul;
pub use mul::mul;

mod shl;
pub use shl::shl;

mod shr;
pub use shr::shr;

mod sub;
pub use sub::sub;

mod ternary;
pub use ternary::ternary;

mod and;
pub use and::and;
