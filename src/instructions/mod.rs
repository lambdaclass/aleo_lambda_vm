// Here we enforce to use the function from the module to avoid add::add-like
// usage to promote instructions::add-like usage.
mod add;
pub use add::add;

mod and;
pub use and::and;

mod cast;
pub use cast::cast;

mod div;
pub use div::div;

mod compare;
pub use compare::compare;
pub use compare::Comparison;

mod hash_psd2;
pub use hash_psd2::hash_psd2;

mod assert;
pub use assert::assert_eq;
pub use assert::assert_neq;

mod is_eq;
pub use is_eq::is_eq;
pub use is_eq::is_neq;

mod mul;
pub use mul::mul;

mod nand;
pub use nand::nand;

mod nor;
pub use nor::nor;

mod or;
pub use or::or;

mod shl;
pub use shl::shl;

mod shr;
pub use shr::shr;

mod sub;
pub use sub::sub;

mod ternary;
pub use ternary::ternary;

mod xor;
pub use xor::xor;
