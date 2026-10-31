-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY job_due ON one.job (run_after) WHERE state = 'pending';
