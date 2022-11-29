use super::{AddressGadget, UInt64Gadget};
use simpleworks::types::value::SimpleworksValueType;
use std::collections::HashMap;

pub type RecordFieldsType = HashMap<String, SimpleworksValueType>;

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: AddressGadget,
    pub gates: UInt64Gadget,
    // custom fields
    pub entries: RecordFieldsType,
}
