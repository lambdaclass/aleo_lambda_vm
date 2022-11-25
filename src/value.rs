use anyhow::{anyhow, bail};
use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CircuitParamType {
    /// A publicly-visible type.
    Public(SimpleworksValueType),
    /// A private type.
    Private(SimpleworksValueType),
    /// A constant type for the circuit.
    Constant(SimpleworksValueType),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SimpleworksValueType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Address([u8; 63]),
}

impl TryFrom<&String> for SimpleworksValueType {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if value.ends_with("u8") {
            let v = value.trim_end_matches("u8");
            let value_int = v.parse::<u8>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U8(value_int));
        } else if value.ends_with("u16") {
            let v = value.trim_end_matches("u16");
            let value_int = v.parse::<u16>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U16(value_int));
        } else if value.ends_with("u32") {
            let v = value.trim_end_matches("u32");
            let value_int = v.parse::<u32>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U32(value_int));
        } else if value.ends_with("u64") {
            let v = value.trim_end_matches("u64");
            let value_int = v.parse::<u64>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U64(value_int));
        } else if value.ends_with("u128") {
            let v = value.trim_end_matches("u128");
            let value_int = v.parse::<u128>().map_err(|e| anyhow!("{}", e))?;
            return Ok(SimpleworksValueType::U128(value_int));
        }
        bail!("Unknown type")
    }
}
