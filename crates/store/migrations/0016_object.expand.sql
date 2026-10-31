-- T-5, OP-6, OP-7 (3), T-32 (3, 4, 6)
SET LOCAL ROLE one_owner;

CREATE TABLE one.object (
  owner text NOT NULL,
  id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'superseded', 'deleted')),
  retention_class text NOT NULL CHECK (retention_class IN ('one_memory', 'one_model', 'one_observation',
    'one_sensitive', 'one_provider_trace', 'one_browser_profile', 'one_training_lineage')),
  region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]{1,16})?$'),
  record_key_id uuid NOT NULL,
  dek_id uuid NOT NULL,
  ciphertext_len integer NOT NULL CHECK (ciphertext_len >= 0),
  promise_version integer NOT NULL CHECK (promise_version >= 1),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
  PRIMARY KEY (owner, id),
  FOREIGN KEY (owner, record_key_id) REFERENCES one.record_key (owner, record_key_id),
  FOREIGN KEY (owner, dek_id) REFERENCES one.class_dek (owner, dek_id)
);

ALTER TABLE one.object ENABLE ROW LEVEL SECURITY;
ALTER TABLE one.object FORCE ROW LEVEL SECURITY;
REVOKE ALL ON one.object FROM PUBLIC;
CREATE POLICY rows ON one.object AS PERMISSIVE USING (true);
CREATE POLICY owner_scope ON one.object AS RESTRICTIVE TO one_app
  USING (owner = (SELECT one.owner_scope())) WITH CHECK (owner = (SELECT one.owner_scope()));
CREATE POLICY queue_only ON one.object AS RESTRICTIVE TO one_queue USING (false);
GRANT SELECT, INSERT ON one.object TO one_app;
GRANT UPDATE (status, deleted_at) ON one.object TO one_app;

RESET ROLE;
