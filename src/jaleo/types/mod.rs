use indexmap::IndexMap;

mod user_input;
pub use user_input::UserInputValueType;

mod serialize;

pub type Address = [u8; 63];
pub type RecordEntriesMap = IndexMap<String, UserInputValueType>;
