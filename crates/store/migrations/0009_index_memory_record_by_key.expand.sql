-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY memory_record_by_key ON one.memory_record (owner, record_key_id);
