-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id TEXT PRIMARY KEY,
  full_name TEXT,
  email TEXT,
  phone TEXT,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS session_links (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
  linked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- granular “memories” distilled from conversations (facts, preferences, incidents)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_kind') THEN
    CREATE TYPE memory_kind AS ENUM ('fact','preference','incident','medical','legal','summary','other');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS memories (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
  kind memory_kind NOT NULL,
  content TEXT NOT NULL,
  labels TEXT[] NOT NULL DEFAULT '{}',
  source_session TEXT,
  embedding vector(1536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- optional: embed individual messages for deep recall
CREATE TABLE IF NOT EXISTS message_embeddings (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
  content TEXT NOT NULL,
  embedding vector(1536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- speed up similarity search
CREATE INDEX IF NOT EXISTS idx_memories_user ON memories(user_id);
CREATE INDEX IF NOT EXISTS idx_memories_labels ON memories USING GIN(labels);
CREATE INDEX IF NOT EXISTS idx_memories_embed ON memories USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX IF NOT EXISTS idx_msgembed_session ON message_embeddings(session_id);
CREATE INDEX IF NOT EXISTS idx_msgembed_embed ON message_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_msgembed_embed;
DROP INDEX IF EXISTS idx_msgembed_session;
DROP TABLE IF EXISTS message_embeddings;

DROP INDEX IF EXISTS idx_memories_embed;
DROP INDEX IF EXISTS idx_memories_labels;
DROP INDEX IF EXISTS idx_memories_user;
DROP TABLE IF EXISTS memories;

DROP TABLE IF EXISTS session_links;
DROP TABLE IF EXISTS user_profiles;

DROP EXTENSION IF EXISTS vector;
-- +goose StatementEnd
