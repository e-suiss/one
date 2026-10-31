-- T-32 (3, 4, 6, 10), OP-3, OP-4, OP-12, OP-30, T-27 (6, 7), PV-19
SET LOCAL ROLE one_owner;

CREATE FUNCTION one.owner_scope() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT nullif(current_setting('app.owner', true), '') $$;

CREATE TABLE one.account (
  owner text NOT NULL CHECK (owner ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]{1,16})?$'),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  PRIMARY KEY (owner)
);

CREATE TABLE one.class_dek (
  owner text NOT NULL,
  dek_id uuid NOT NULL,
  retention_class text NOT NULL CHECK (retention_class IN ('one_memory', 'one_model', 'one_observation',
    'one_sensitive', 'one_provider_trace', 'one_browser_profile', 'one_training_lineage')),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_:.-]{1,200}$'),
  wrapped_dek bytea CHECK (octet_length(wrapped_dek) BETWEEN 40 AND 512),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((wrapped_dek IS NULL) = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, dek_id),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

CREATE TABLE one.record_key (
  owner text NOT NULL,
  record_key_id uuid NOT NULL,
  dek_id uuid NOT NULL,
  wrapped_record_key bytea CHECK (octet_length(wrapped_record_key) = 40),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((wrapped_record_key IS NULL) = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id)
);

CREATE TABLE one.record (
  owner text NOT NULL,
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  supersedes uuid,
  status text NOT NULL CHECK (status IN ('active', 'superseded', 'deleted')),
  retention_class text NOT NULL CHECK (retention_class IN ('one_memory', 'one_model', 'one_observation',
    'one_sensitive', 'one_provider_trace', 'one_browser_profile', 'one_training_lineage')),
  region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]{1,16})?$'),
  record_key_id uuid NOT NULL,
  dek_id uuid NOT NULL,
  ciphertext bytea NOT NULL,
  ciphertext_len integer NOT NULL CHECK (ciphertext_len = octet_length(ciphertext)),
  promise_version integer NOT NULL CHECK (promise_version >= 1),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((supersedes IS NULL) = (version = 1)),
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, id),
  FOREIGN KEY (owner, record_key_id) REFERENCES one.record_key (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id),
  FOREIGN KEY (owner, supersedes) REFERENCES one.record (owner, id)
);

CREATE TABLE one.outbox (
  owner text NOT NULL,
  id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,127}$'),
  idempotency_key bytea NOT NULL CHECK (octet_length(idempotency_key) = 32),
  ciphertext bytea NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sent')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  run_after timestamptz NOT NULL DEFAULT now(),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, id),
  UNIQUE (owner, idempotency_key),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

CREATE TABLE one.idempotency (
  owner text NOT NULL,
  idempotency_key bytea NOT NULL CHECK (octet_length(idempotency_key) = 32),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  ciphertext bytea,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, idempotency_key),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

CREATE TABLE one.job (
  owner text NOT NULL,
  job_id uuid NOT NULL,
  job_kind text NOT NULL CHECK (job_kind IN ('consolidation', 'personal_training', 'reembedding', 'export',
    'shred')),
  idempotency_key bytea NOT NULL CHECK (octet_length(idempotency_key) = 32),
  permission_id uuid,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'held', 'done', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  run_after timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  ciphertext bytea,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((state = 'running') = (lease_until IS NOT NULL)),
  PRIMARY KEY (owner, job_id),
  UNIQUE (owner, idempotency_key),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

CREATE TABLE one.legal_hold (
  owner text NOT NULL,
  id uuid NOT NULL,
  retention_class text NOT NULL CHECK (retention_class IN ('one_memory', 'one_model', 'one_observation',
    'one_sensitive', 'one_provider_trace', 'one_browser_profile', 'one_training_lineage')),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  PRIMARY KEY (owner, id),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['account', 'class_dek', 'record_key', 'record', 'outbox', 'idempotency', 'job',
                           'legal_hold'] LOOP
    EXECUTE format('ALTER TABLE one.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE one.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON one.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON one.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY owner_scope ON one.%I AS RESTRICTIVE TO one_app '
                   'USING (owner = (SELECT one.owner_scope())) '
                   'WITH CHECK (owner = (SELECT one.owner_scope()))', t);
  END LOOP;
END
$$;

CREATE POLICY queue_only ON one.account AS RESTRICTIVE TO one_queue USING (false);
CREATE POLICY queue_only ON one.class_dek AS RESTRICTIVE TO one_queue USING (false);
CREATE POLICY queue_only ON one.record_key AS RESTRICTIVE TO one_queue USING (false);
CREATE POLICY queue_only ON one.record AS RESTRICTIVE TO one_queue USING (false);
CREATE POLICY queue_only ON one.idempotency AS RESTRICTIVE TO one_queue USING (false);
CREATE POLICY queue_only ON one.legal_hold AS RESTRICTIVE TO one_queue USING (false);

REVOKE ALL ON FUNCTION one.owner_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION one.owner_scope() TO one_app;

GRANT SELECT, INSERT ON one.account, one.class_dek, one.record_key, one.record, one.outbox, one.idempotency,
  one.job, one.legal_hold TO one_app;
GRANT UPDATE (deleted_at) ON one.account TO one_app;
GRANT UPDATE (kek_id, wrapped_dek, deleted_at) ON one.class_dek TO one_app;
GRANT UPDATE (wrapped_record_key, deleted_at) ON one.record_key TO one_app;
GRANT UPDATE (status, deleted_at) ON one.record TO one_app;
GRANT UPDATE (ciphertext) ON one.idempotency TO one_app;
GRANT UPDATE (state, attempts, run_after, lease_until) ON one.job TO one_app;
GRANT UPDATE (deleted_at) ON one.legal_hold TO one_app;

GRANT SELECT ON one.outbox, one.job TO one_queue;
GRANT UPDATE (state, attempts, run_after) ON one.outbox TO one_queue;
GRANT UPDATE (state, attempts, run_after, lease_until) ON one.job TO one_queue;

RESET ROLE;
