-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY derivation_by_source ON one.derivation (owner, source_id);
