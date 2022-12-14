use super::{Deployment, Program, Transition};
use crate::VariableType;
use serde::{ser::Error, Deserialize, Serialize};

// Until we settle on one of the alternatives depending on performance, we have 2 variants for deployment transactions:
// Transaction::Deployment generates verifying keys offline and sends them to the network along with the program
// Transaction::Source just sends the program after being validated, and keys are generated on-chain
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Transaction {
    Deployment {
        id: String,
        deployment: Box<Deployment>,
    },
    Source {
        id: String,
        program: Box<Program>,
    },
    Execution {
        id: String,
        transitions: Vec<Transition>,
    },
}

impl Transaction {
    pub fn id(&self) -> &str {
        match self {
            Transaction::Deployment { id, .. } => id,
            Transaction::Execution { id, .. } => id,
            Transaction::Source { id, .. } => id,
        }
    }

    pub fn output_records(&self) -> Vec<VariableType> {
        if let Transaction::Execution { transitions, .. } = self {
            transitions
                .iter()
                .flat_map(|transition| transition.output_records())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// If the transaction is an execution, return the list of input record origins
    /// (in case they are record commitments).
    pub fn origin_commitments(&self) -> Vec<String> {
        if let Transaction::Execution {
            ref transitions, ..
        } = self
        {
            transitions
                .iter()
                .flat_map(|transition| transition.origins())
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transaction::Deployment { id, deployment } => {
                write!(f, "Deployment({},{})", id, deployment.program.id())
            }
            Transaction::Source { id, program } => {
                write!(f, "Source({},{})", id, program.id())
            }
            Transaction::Execution { id, transitions } => {
                let transition = transitions.first().ok_or_else(|| {
                    std::fmt::Error::custom("Error getting the first transition while formatting")
                })?;
                write!(f, "Execution({},{})", &transition.program_id, id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Transaction;
    use crate::jaleo::{generate_deployment, generate_execution, PrivateKey, Program};
    use anyhow::{anyhow, Result};
    use simpleworks::types::value::{Address, RecordEntriesMap, SimpleworksValueType};
    use std::str::FromStr;

    fn sample_address(n: u64) -> (String, Address) {
        let mut address_bytes = [0_u8; 63];
        let address_string =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_string, address_bytes)
    }

    fn sample_deployment_transaction() -> Result<(String, Transaction)> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let deployment = generate_deployment(&program_string)?;
        let transaction_id = "deployment_transaction";
        let transaction = Transaction::Deployment {
            id: transaction_id.to_owned(),
            deployment: Box::new(deployment),
        };
        Ok((transaction_id.to_owned(), transaction))
    }

    fn sample_source_transaction() -> Result<(String, Transaction)> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let program_string = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        let program = Program::from_str(&program_string)?;
        let transaction_id = "source_transaction";
        let transaction = Transaction::Source {
            id: transaction_id.to_owned(),
            program: Box::new(program),
        };
        Ok((transaction_id.to_owned(), transaction))
    }

    fn sample_execution_transaction() -> Result<(String, Transaction)> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/credits.aleo");
        let path = path.to_str().ok_or_else(
            || anyhow! {"Error passing PathBuf into str when sampling an execution transaction"},
        )?;

        let rng = &mut simpleworks::marlin::generate_rand();

        let (_sender_address_string, sender_address_bytes) = sample_address(0);
        let amount_to_transfer = 1_u64;
        let (_receiver_address_string, receiver_address_bytes) = sample_address(0);

        let user_inputs = vec![
            SimpleworksValueType::Record {
                owner: sender_address_bytes,
                gates: amount_to_transfer,
                entries: RecordEntriesMap::default(),
            },
            SimpleworksValueType::Address(receiver_address_bytes),
            SimpleworksValueType::U64(amount_to_transfer),
        ];

        let private_key = PrivateKey::new(rng).map_err(|e| anyhow!{"Error creating a private key when sampling an execution transaction: {e:?}"})?;
        let transitions = generate_execution(path, "transfer", &user_inputs, &private_key, rng)?;
        let transaction_id = "execution_transaction";
        let transaction = Transaction::Execution {
            id: transaction_id.to_owned(),
            transitions,
        };
        Ok((transaction_id.to_owned(), transaction))
    }

    #[test]
    fn test_deployment_transaction_id() {
        let (transaction_id, transaction) = sample_deployment_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Deployment {
                id: _,
                deployment: _
            }
        ));
        assert_eq!(transaction_id, transaction.id());
    }

    #[test]
    fn test_source_transaction_id() {
        let (transaction_id, transaction) = sample_source_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Source { id: _, program: _ }
        ));
        assert_eq!(transaction_id, transaction.id());
    }

    #[test]
    fn test_execution_transaction_id() {
        let (transaction_id, transaction) = sample_execution_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Execution {
                id: _,
                transitions: _
            }
        ));
        assert_eq!(transaction_id, transaction.id());
    }

    #[test]
    fn test_output_records_should_be_empty_for_deployment_transactions() {
        let (_transaction_id, transaction) = sample_deployment_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Deployment {
                id: _,
                deployment: _
            }
        ));
        assert!(transaction.output_records().is_empty());
    }

    #[test]
    fn test_output_records_should_be_empty_for_source_transactions() {
        let (_transaction_id, transaction) = sample_source_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Source { id: _, program: _ }
        ));
        assert!(transaction.output_records().is_empty());
    }

    #[test]
    fn test_output_records_should_not_be_empty_for_execution_transactions() {
        let (_transaction_id, transaction) = sample_execution_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Execution {
                id: _,
                transitions: _
            }
        ));
        assert!(!transaction.output_records().is_empty());
    }

    #[test]
    fn test_origin_commitments_should_be_empty_for_deployment_transactions() {
        let (_transaction_id, transaction) = sample_deployment_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Deployment {
                id: _,
                deployment: _
            }
        ));
        assert!(transaction.origin_commitments().is_empty());
    }

    #[test]
    fn test_origin_commitments_should_be_empty_for_source_transactions() {
        let (_transaction_id, transaction) = sample_source_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Source { id: _, program: _ }
        ));
        assert!(transaction.origin_commitments().is_empty());
    }

    #[test]
    fn test_origin_commitments_should_not_be_empty_for_execution_transactions() {
        let (_transaction_id, transaction) = sample_execution_transaction().unwrap();

        assert!(matches!(
            transaction,
            Transaction::Execution {
                id: _,
                transitions: _
            }
        ));
        assert!(!transaction.origin_commitments().is_empty());
    }
}
