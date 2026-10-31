-- M-6, M-11, M-12, M-25, C-20, C-21, OP-5, OP-24, T-32 (3, 4, 6)
SET LOCAL ROLE one_owner;

CREATE TABLE one.memory_record (
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
  FOREIGN KEY (owner, supersedes) REFERENCES one.memory_record (owner, id)
);

CREATE TABLE one.memory_edge (
  owner text NOT NULL,
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
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
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, id, version),
  FOREIGN KEY (owner, record_key_id) REFERENCES one.record_key (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id)
);

CREATE TABLE one.episode (
  owner text NOT NULL,
  id uuid NOT NULL,
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
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, id),
  FOREIGN KEY (owner, record_key_id) REFERENCES one.record_key (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id)
);

CREATE TABLE one.derivation (
  owner text NOT NULL,
  id uuid NOT NULL,
  source_id uuid NOT NULL,
  source_version integer NOT NULL CHECK (source_version >= 1),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, id, source_id, source_version),
  FOREIGN KEY (owner) REFERENCES one.account (owner)
);

CREATE TABLE one.index_part (
  owner text NOT NULL,
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  supersedes uuid,
  status text NOT NULL CHECK (status IN ('active', 'superseded', 'deleted')),
  retention_class text NOT NULL CHECK (retention_class IN ('one_memory', 'one_model', 'one_observation',
    'one_sensitive', 'one_provider_trace', 'one_browser_profile', 'one_training_lineage')),
  index_part_no integer NOT NULL CHECK (index_part_no >= 0),
  embedding_model text CHECK (embedding_model ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  embedding_model_version text CHECK (embedding_model_version ~ '^[A-Za-z0-9_.:+-]{1,64}$'),
  record_key_id uuid NOT NULL,
  dek_id uuid NOT NULL,
  ciphertext bytea NOT NULL,
  ciphertext_len integer NOT NULL CHECK (ciphertext_len = octet_length(ciphertext)),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((embedding_model IS NULL) = (embedding_model_version IS NULL)),
  CHECK ((supersedes IS NULL) = (version = 1)),
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, id),
  FOREIGN KEY (owner, record_key_id) REFERENCES one.record_key (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id),
  FOREIGN KEY (owner, supersedes) REFERENCES one.index_part (owner, id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['memory_record', 'memory_edge', 'episode', 'derivation', 'index_part'] LOOP
    EXECUTE format('ALTER TABLE one.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE one.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON one.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON one.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY owner_scope ON one.%I AS RESTRICTIVE TO one_app '
                   'USING (owner = (SELECT one.owner_scope())) '
                   'WITH CHECK (owner = (SELECT one.owner_scope()))', t);
    EXECUTE format('CREATE POLICY queue_only ON one.%I AS RESTRICTIVE TO one_queue USING (false)', t);
    EXECUTE format('GRANT SELECT, INSERT ON one.%I TO one_app', t);
  END LOOP;
END
$$;

GRANT UPDATE (status, deleted_at) ON one.memory_record, one.memory_edge, one.episode, one.index_part TO one_app;

RESET ROLE;
