use super::{
    republisher::{RepublishError, RepublishOutcome},
    retrying_republisher::RepublishInfo,
};

pub(super) type RepublishResult = Result<RepublishInfo, RepublishError>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepublishSummary {
    total_count: usize,
    success_count: usize,
    skipped_count: usize,
    missing_count: usize,
    invalid_signed_packet_count: usize,
    failed_count: usize,
}

impl RepublishSummary {
    pub(super) fn record(&mut self, result: RepublishResult) {
        self.total_count += 1;

        match result {
            Ok(RepublishInfo {
                outcome: RepublishOutcome::Published,
                ..
            }) => self.success_count += 1,
            Ok(RepublishInfo {
                outcome: RepublishOutcome::Skipped,
                ..
            }) => self.skipped_count += 1,
            Ok(RepublishInfo {
                outcome: RepublishOutcome::Missing,
                ..
            }) => self.missing_count += 1,
            Ok(RepublishInfo {
                outcome: RepublishOutcome::InvalidSignedPacket,
                ..
            }) => self.invalid_signed_packet_count += 1,
            Err(_) => self.failed_count += 1,
        }
    }

    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.total_count += other.total_count;
        self.success_count += other.success_count;
        self.skipped_count += other.skipped_count;
        self.missing_count += other.missing_count;
        self.invalid_signed_packet_count += other.invalid_signed_packet_count;
        self.failed_count += other.failed_count;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Whether any key was missing, invalid, or failed to publish.
    pub fn has_issues(&self) -> bool {
        self.missing_count > 0 || self.invalid_signed_packet_count > 0 || self.failed_count > 0
    }
}

#[cfg(test)]
impl RepublishSummary {
    /// Number of republish attempts.
    pub fn len(&self) -> usize {
        self.total_count
    }

    /// Number of successfully published keys.
    pub fn success_count(&self) -> usize {
        self.success_count
    }

    /// Number of keys that did not satisfy the republish condition.
    pub fn skipped_count(&self) -> usize {
        self.skipped_count
    }

    /// Number of keys that are missing and could not be republished.
    pub fn missing_count(&self) -> usize {
        self.missing_count
    }

    /// Number of resolved packets that were invalid.
    pub fn invalid_signed_packet_count(&self) -> usize {
        self.invalid_signed_packet_count
    }

    /// Number of keys that failed to publish.
    pub fn failed_count(&self) -> usize {
        self.failed_count
    }
}

#[cfg(test)]
mod tests {
    use super::{RepublishError, RepublishInfo, RepublishOutcome, RepublishSummary};

    #[test]
    fn records_and_merges_republish_outcomes() {
        let mut summary = RepublishSummary::default();
        summary.record(Ok(RepublishInfo::new(RepublishOutcome::Published, 1)));
        summary.record(Ok(RepublishInfo::new(RepublishOutcome::Skipped, 1)));
        assert!(!summary.has_issues());

        let mut other = RepublishSummary::default();
        other.record(Ok(RepublishInfo::new(RepublishOutcome::Missing, 1)));
        other.record(Ok(RepublishInfo::new(
            RepublishOutcome::InvalidSignedPacket,
            1,
        )));
        other.record(Err(RepublishError::InsufficientlyPublished {
            published_nodes_count: 1,
        }));

        let summary = summary.merge(other);

        assert_eq!(summary.len(), 5);
        assert_eq!(summary.success_count(), 1);
        assert_eq!(summary.skipped_count(), 1);
        assert_eq!(summary.missing_count(), 1);
        assert_eq!(summary.invalid_signed_packet_count(), 1);
        assert_eq!(summary.failed_count(), 1);
        assert!(summary.has_issues());
    }
}
