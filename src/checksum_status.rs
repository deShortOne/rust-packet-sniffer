#[derive(Debug, PartialEq)]
pub enum ChecksumStatus {
    FullyMatched,
    PartialMatch,
    NoMatch(u16),
}
