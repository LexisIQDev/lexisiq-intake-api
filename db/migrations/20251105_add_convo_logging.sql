-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_activity TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_session_time ON messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_session_time ON audit_events(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);

CREATE MATERIALIZED VIEW IF NOT EXISTS transcripts AS
SELECT session_id, jsonb_agg(jsonb_build_object(
  'role', role,
  'content', content,
  'ts', created_at
) ORDER BY created_at) AS turns
FROM messages GROUP BY session_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP MATERIALIZED VIEW IF EXISTS transcripts;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd
