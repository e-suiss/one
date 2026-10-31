-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY job_lease ON one.job (lease_until) WHERE state = 'running';
