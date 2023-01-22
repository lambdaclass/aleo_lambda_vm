use crate::jaleo::{EncryptedRecord, Field, Record, UserInputValueType};
use std::fmt::Display;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum VariableType {
    /// The plaintext.
    Public(UserInputValueType),
    /// The ciphertext.
    // TODO: Replace UserInputValueType with Ciphertext.
    Private(UserInputValueType),
    /// The serial number, and the record.
    // The serial number is an option because output records don't have serial numbers.
    Record(Option<Field>, Record),
    EncryptedRecord(EncryptedRecord),
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
                    data,
                    nonce,
                },
            ) => Ok(UserInputValueType::Record(Record {
                owner: *owner,
                gates: *gates,
                data: data.clone(),
                nonce: *nonce,
            })),
            VariableType::EncryptedRecord(_) => {
                bail!("value() for EncryptedRecord is not implemented yet.")
            } // XXX::ExternalRecord(value) => Ok(value.to_string()),
        }
    }
}

impl Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableType::Public(v) | VariableType::Private(v) => UserInputValueType::fmt(v, f),
            VariableType::Record(_, v) => Record::fmt(v, f),
            VariableType::EncryptedRecord(v) => EncryptedRecord::fmt(v, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::from_str;
    use simpleworks::{fields::serialize_field_element, gadgets::ConstraintF};

    use crate::{
        helpers::{self, to_address},
        jaleo::{Record, RecordEntriesMap, UserInputValueType},
        VariableType,
    };

    #[test]
    fn test_serialize_public_variable_type() {
        let public_variable = VariableType::Public(UserInputValueType::U8(1));

        let serialized_public_variable = serde_json::to_string(&public_variable).unwrap();

        assert_eq!(serialized_public_variable, r#"{"Public":"1u8"}"#);
    }

    #[test]
    fn test_serialize_private_variable_type() {
        let private_variable = VariableType::Private(UserInputValueType::U8(1));

        let serialized_private_variable = serde_json::to_string(&private_variable).unwrap();

        assert_eq!(serialized_private_variable, r#"{"Private":"1u8"}"#);
    }

    #[test]
    fn test_serialize_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = helpers::random_nonce();
        let record_variable = VariableType::Record(
            None,
            Record::new(
                to_address(primitive_address),
                gates,
                RecordEntriesMap::default(),
                Some(nonce),
            ),
        );

        let serialized_record_variable = serde_json::to_string(&record_variable).unwrap();

        let nonce_as_string = nonce.to_string();
        assert_eq!(
            serialized_record_variable,
            format!("{{\"Record\":[null,{{\"owner\":\"aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0\",\"gates\":\"1u64\",\"data\":{{}},\"nonce\":\"{nonce_as_string}\"}}]}}")
        );
    }

    #[test]
    #[ignore = "This test should pass (deserialization needs to handle this error)"]
    fn test_cannot_serialize_a_public_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = helpers::random_nonce();
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
    #[ignore = "This test should pass (deserialization needs to handle this error)"]
    fn test_cannot_serialize_a_private_record_variable_type() {
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = helpers::random_nonce();
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
        let serialized_public_variable = r#"{"Public":"1u8"}"#;

        let public_variable: VariableType =
            serde_json::from_str(serialized_public_variable).unwrap();

        assert_eq!(
            public_variable,
            VariableType::Public(UserInputValueType::U8(1))
        );
    }

    #[test]
    fn test_deserialize_private_variable_type() {
        let serialized_private_variable = r#"{"Private":"1u8"}"#;

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
        let nonce = helpers::random_nonce();
        let nonce_as_string = nonce.to_string();
        let serialized_record_variable = format!(
            r#"{{"Record":[null,{{"owner":"{primitive_address}","gates":"1u64","data":{{}},"nonce":"{nonce_as_string}"}}]}}"#
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
        let nonce = helpers::random_nonce();
        let nonce_as_string = nonce.to_string();
        let serialized_public_record_variable = format!(
            r#"{{"Public":{{"owner":"{primitive_address}","gates":"1u64","data":{{}},"nonce":"{nonce_as_string}"}}"#,
        );

        assert!(serde_json::from_str::<VariableType>(&serialized_public_record_variable).is_err());
    }

    #[test]
    fn test_cannot_deserialize_a_private_record_variable_type() {
        let primitive_address = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0";
        let nonce = helpers::random_nonce();
        let nonce_as_string = nonce.to_string();
        let serialized_private_record_variable = format!(
            r#"{{"Private":{{"owner":"{primitive_address}","gates":"1u64","entries":{{}},"nonce":"{nonce_as_string}"}}"#,
        );

        assert!(serde_json::from_str::<VariableType>(&serialized_private_record_variable).is_err())
    }

    #[test]
    fn test_bincode_serialization() {
        let public_variable = VariableType::Public(UserInputValueType::U8(1));
        let private_variable = VariableType::Private(UserInputValueType::U8(1));
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = helpers::random_nonce();
        let record_variable = VariableType::Record(
            None,
            Record::new(
                to_address(primitive_address),
                gates,
                RecordEntriesMap::default(),
                Some(nonce),
            ),
        );

        assert!(bincode::serialize(&public_variable).is_ok());
        assert!(bincode::serialize(&private_variable).is_ok());
        assert!(bincode::serialize(&record_variable).is_ok());
    }

    #[test]
    fn test_bincode_deserialization() {
        let public_variable = VariableType::Public(UserInputValueType::U8(1));
        let private_variable = VariableType::Private(UserInputValueType::U8(1));
        let primitive_address =
            "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z0".to_owned();
        let gates = 1;
        let nonce = helpers::random_nonce();
        let record_variable = VariableType::Record(
            None,
            Record::new(
                to_address(primitive_address),
                gates,
                RecordEntriesMap::default(),
                Some(nonce),
            ),
        );

        let serialized_public_variable = bincode::serialize(&public_variable).unwrap();
        let serialized_private_variable = bincode::serialize(&private_variable).unwrap();
        let serialized_record_variable = bincode::serialize(&record_variable).unwrap();

        assert_eq!(
            bincode::deserialize::<VariableType>(&serialized_public_variable).unwrap(),
            public_variable
        );
        assert_eq!(
            bincode::deserialize::<VariableType>(&serialized_private_variable).unwrap(),
            private_variable
        );
        assert_eq!(
            bincode::deserialize::<VariableType>(&serialized_record_variable).unwrap(),
            record_variable
        );
    }
}
