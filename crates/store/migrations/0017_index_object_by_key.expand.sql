-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY object_by_key ON one.object (owner, record_key_id);
