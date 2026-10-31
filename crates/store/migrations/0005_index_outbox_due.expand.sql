-- no-transaction
-- T-32 (7, 10), OP-27
CREATE INDEX CONCURRENTLY outbox_due ON one.outbox (run_after) WHERE state = 'pending';
