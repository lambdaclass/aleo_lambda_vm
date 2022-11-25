use simpleworks::types::value::SimpleworksValueType;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CircuitParamType {
    /// A publicly-visible type.
    Public(SimpleworksValueType),
    /// A private type.
    Private(SimpleworksValueType),
    /// A constant type for the circuit.
    Constant(SimpleworksValueType),
}
