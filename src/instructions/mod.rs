// Here we enforce to use the function from the module to avoid add::add-like
// usage to promote instructions::add-like usage.
mod add;
pub use add::add;

mod cast;
pub use cast::cast;

mod sub;
pub use sub::sub;
