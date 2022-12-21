use crate::jaleo::{Field, Record, UserInputValueType};
use std::fmt::Display;

use anyhow::Result;
use serde::{
    de,
    ser::{self, SerializeStruct},
    Deserialize, Serialize,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariableType {
    /// The plaintext hash and (optional) plaintext.
    // Constant(ConstraintF, UserInputValueType),
    /// The plaintext.
    Public(UserInputValueType),
    /// The ciphertext.
    // TODO: Replace UserInputValueType with Ciphertext.
    Private(UserInputValueType),
    /// The serial number, and the record.
    // The serial number is an option because output records don't have serial numbers.
    Record(Option<Field>, Record),
    // The input commitment to the external record. Note: This is **not** the record commitment.
    // ExternalRecord(ConstraintF),
}

impl VariableType {
    pub fn value(&self) -> Result<UserInputValueType> {
        match self {
            // XXX::Constant(_, value) => Ok(value.to_string()),
            VariableType::Public(value) | VariableType::Private(value) => Ok(value.clone()),
            VariableType::Record(
                _,
                Record {
                    owner,
                    gates,
                    entries,
                    nonce,
                },
            ) => Ok(UserInputValueType::Record(Record {
                owner: *owner,
                gates: *gates,
                entries: entries.clone(),
                nonce: *nonce,
            })),
            // XXX::ExternalRecord(value) => Ok(value.to_string()),
        }
    }
}

impl Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableType::Public(v) | VariableType::Private(v) => UserInputValueType::fmt(v, f),
            VariableType::Record(_, v) => Record::fmt(v, f),
        }
    }
}

impl Serialize for VariableType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            VariableType::Public(UserInputValueType::Record(..))
            | VariableType::Private(UserInputValueType::Record(..)) => Err(ser::Error::custom(
                "Cannot serialize a record as a public or private variable",
            )),
            VariableType::Public(v) => {
                let mut s = serializer.serialize_struct("PublicVariableType", 2)?;
                s.serialize_field("type", "public")?;
                s.serialize_field("value", v)?;
                s.end()
            }
            VariableType::Private(v) => {
                let mut s = serializer.serialize_struct("PublicVariableType", 2)?;
                s.serialize_field("type", "private")?;
                s.serialize_field("value", v)?;
                s.end()
            }
            VariableType::Record(_, v) => Record::serialize(v, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for VariableType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let request = serde_json::Value::deserialize(deserializer)?;
        if let Some(variable_type_value) = request.get("type") {
            let value: UserInputValueType = serde_json::from_value(
                request
                    .get("value")
                    .ok_or_else(|| de::Error::custom("Missing type field"))?
                    .clone(),
            )
            .map_err(de::Error::custom)?;
            match (variable_type_value.as_str(), value) {
                (_, UserInputValueType::Record(..)) => Err(de::Error::custom(
                    "Cannot deserialize a record as a public or private variable",
                )),
                (Some("public"), value) => Ok(VariableType::Public(value)),
                (Some("private"), value) => Ok(VariableType::Private(value)),
                _ => Err(de::Error::custom("Invalid variable type")),
            }
        } else {
            let record: Record = serde_json::from_value(request).map_err(de::Error::custom)?;
            Ok(VariableType::Record(None, record))
        }
    }
}

#[cfg(test)]
mod tests {
    use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};

    use crate::{
        helpers::to_address,
        jaleo::{Record, RecordEntriesMap, UserInputValueType},
        VariableType,
    };

    #[test]
    fn test_serialize_public_variable_type() {
        let public_variable = VariableType::Public(UserInputValueType::U8(1));

        let serialized_public_variable = serde_json::to_string(&public_variable).unwrap();

        assert_eq!(
            serialized_public_variable,
            r#"{"type":"public","value":"1u8"}"#
        );
    }

    #[test]
    fn test_serialize_private_variable_type() {
        let private_variable = VariableType::Private(UserInputValueType::U8(1));

        let serialized_private_variable = serde_json::to_string(&private_variable).unwrap();

        assert_eq!(
            serialized_private_variable,
            r#"{"type":"private","value":"1u8"}"#
        );
    }

    #[test]
    fn test_serialize_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = ConstraintF::default();
        let encoded_nonce = hex::encode(serialize_field_element(nonce).unwrap());
        let record_variable = VariableType::Record(
            None,
            Record::new(
                to_address(primitive_address.clone()),
                gates,
                RecordEntriesMap::default(),
                Some(nonce),
            ),
        );

        let serialized_record_variable = serde_json::to_string(&record_variable).unwrap();

        assert_eq!(
            serialized_record_variable,
            format!(
                r#"{{"owner":"{primitive_address}","gates":"1u64","entries":{{}},"nonce":"{encoded_nonce}"}}"#
            )
        );
    }

    #[test]
    fn test_cannot_serialize_a_public_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = ConstraintF::default();
        let public_record_variable = VariableType::Public(UserInputValueType::Record(Record::new(
            to_address(primitive_address),
            gates,
            RecordEntriesMap::default(),
            Some(nonce),
        )));

        let error = serde_json::to_string(&public_record_variable).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Cannot serialize a record as a public or private variable"
        );
    }

    #[test]
    fn test_cannot_serialize_a_private_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = ConstraintF::default();
        let private_record_variable =
            VariableType::Private(UserInputValueType::Record(Record::new(
                to_address(primitive_address),
                gates,
                RecordEntriesMap::default(),
                Some(nonce),
            )));

        let error = serde_json::to_string(&private_record_variable).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Cannot serialize a record as a public or private variable"
        );
    }

    #[test]
    fn test_deserialize_public_variable_type() {
        let serialized_public_variable = r#"{"type":"public","value":"1u8"}"#;

        let public_variable: VariableType =
            serde_json::from_str(serialized_public_variable).unwrap();

        assert_eq!(
            public_variable,
            VariableType::Public(UserInputValueType::U8(1))
        );
    }

    #[test]
    fn test_deserialize_private_variable_type() {
        let serialized_private_variable = r#"{"type":"private","value":"1u8"}"#;

        let private_variable: VariableType =
            serde_json::from_str(serialized_private_variable).unwrap();

        assert_eq!(
            private_variable,
            VariableType::Private(UserInputValueType::U8(1))
        );
    }

    #[test]
    fn test_deserialize_record_variable_type() {
        let primitive_address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
        let gates = 1;
        let nonce = ConstraintF::default();
        let encoded_nonce = hex::encode(serialize_field_element(nonce).unwrap());
        let serialized_record_variable = format!(
            r#"{{"owner":"{primitive_address}","gates":"1u64","entries":{{}},"nonce":"{encoded_nonce}"}}"#
        );

        let record_variable: VariableType =
            serde_json::from_str(&serialized_record_variable).unwrap();

        assert_eq!(
            record_variable,
            VariableType::Record(
                None,
                Record::new(
                    to_address(primitive_address.to_owned()),
                    gates,
                    RecordEntriesMap::default(),
                    Some(nonce),
                )
            )
        );
    }

    #[test]
    fn test_cannot_deserialize_a_public_record_variable_type() {
        let primitive_address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
        let nonce = ConstraintF::default();
        let encoded_nonce = hex::encode(serialize_field_element(nonce).unwrap());
        let serialized_public_record_variable = format!(
            r#"{{"type":"public","value": {{"owner": "{primitive_address}","gates": "0u64","entries": {{}},"nonce": "{encoded_nonce}"}}}}"#,
        );

        let error =
            serde_json::from_str::<VariableType>(&serialized_public_record_variable).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Cannot deserialize a record as a public or private variable"
        );
    }

    #[test]
    fn test_cannot_deserialize_a_private_record_variable_type() {
        let primitive_address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
        let nonce = ConstraintF::default();
        let encoded_nonce = hex::encode(serialize_field_element(nonce).unwrap());
        let serialized_private_record_variable = format!(
            r#"{{"type":"private","value": {{"owner": "{primitive_address}","gates": "0u64","entries": {{}},"nonce": "{encoded_nonce}"}}}}"#,
        );

        let error =
            serde_json::from_str::<VariableType>(&serialized_private_record_variable).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Cannot deserialize a record as a public or private variable"
        );
    }
}
