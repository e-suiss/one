-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY index_part_by_key ON one.index_part (owner, record_key_id);
