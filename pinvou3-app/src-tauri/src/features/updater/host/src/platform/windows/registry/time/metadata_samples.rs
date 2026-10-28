//! Native metadata reads derived from the original guarded time transaction.
use super::super::metadata::time_history::{self, HistoryPosition, TimeCheckedBatch};
use super::*;

impl LiveTimeReadSet<'_> {
    /// Identity is necessary in addition to lifetime equality: independently
    /// opened keys or transactions must not be substituted for this read set.
    pub(in crate::platform::windows::registry) fn require_metadata_transaction(
        &self,
        private: &Key,
        transaction: &Handle,
    ) -> Result<()> {
        if !std::ptr::eq(self.private, private) || !std::ptr::eq(self.transaction, transaction) {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    /// Visit actual protected historical samples, never caller-supplied DTOs.
    /// Visitor observations remain provisional until the complete traversal and
    /// final read-set rechecks succeed. This does not authenticate metadata
    /// signatures or waters and cannot authorize acceptance or Root promotion.
    #[allow(dead_code)] // Direct input seam for complete metadata replay.
    pub(in crate::platform::windows::registry) fn visit_metadata_time(
        &self,
        host: &StartedServiceContext,
        visit: impl FnMut(&TimeCheckedBatch<'_, '_, '_>) -> Result<()>,
    ) -> Result<HistoryPosition> {
        self.recheck(host)?;
        let position = time_history::visit_in(self.private, self.transaction, self, host, visit)?;
        self.recheck(host)?;
        Ok(position)
    }
}
