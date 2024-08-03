#[derive(
    Clone,
    Debug,
    derive_more::Display,
    derive_more::Error,
    derive_more::From
)]
pub enum Error {
    InvalidKeyLength
}
