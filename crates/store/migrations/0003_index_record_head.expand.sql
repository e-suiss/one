-- no-transaction
-- T-32 (7, 10), OP-27
CREATE UNIQUE INDEX CONCURRENTLY record_head ON one.record (owner, supersedes) WHERE supersedes IS NOT NULL;
