-- no-transaction
-- T-32 (7, 10), OP-27
CREATE UNIQUE INDEX CONCURRENTLY class_dek_live ON one.class_dek (owner, retention_class) WHERE deleted_at IS NULL;
