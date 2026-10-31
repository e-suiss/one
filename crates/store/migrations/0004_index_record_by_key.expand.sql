-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY record_by_key ON one.record (owner, record_key_id);
