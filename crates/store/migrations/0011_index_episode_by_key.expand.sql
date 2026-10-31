-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY episode_by_key ON one.episode (owner, record_key_id);
