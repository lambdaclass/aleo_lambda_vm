use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Circuit that will test whether the two given numbers are equal
pub struct TestCircuit {
    /// Public input
    pub a: u8,
    /// Private input
    pub b: u8,
}

impl ConstraintSynthesizer<ark_ed_on_bls12_381::Fq> for TestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_ed_on_bls12_381::Fq>,
    ) -> Result<(), SynthesisError> {
        let a = UInt8::new_input(ark_relations::ns!(cs, "a"), || Ok(&self.a))?;

        let b = UInt8::new_witness(ark_relations::ns!(cs, "b"), || Ok(self.b))?;

        a.enforce_equal(&b)?;

        Ok(())
    }
}

fn main() {}

#[test]
fn same_values_should_pass() {
    use ark_relations::r1cs::ConstraintSystem;

    let circuit = TestCircuit { a: 1, b: 1 };

    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        println!("{:?}", cs.which_is_unsatisfied().unwrap().unwrap());
    }
    assert!(is_satisfied);
}

#[test]
fn different_values_should_fail() {
    use ark_relations::r1cs::ConstraintSystem;

    let circuit = TestCircuit { a: 1, b: 2 };

    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(!is_satisfied);
}
