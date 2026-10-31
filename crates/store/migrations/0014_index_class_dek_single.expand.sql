-- no-transaction
-- T-32 (7, 10), OP-27, PV-22 (1)
CREATE UNIQUE INDEX CONCURRENTLY class_dek_single ON one.class_dek (owner, retention_class)
  WHERE deleted_at IS NULL AND retention_class <> 'one_sensitive';
