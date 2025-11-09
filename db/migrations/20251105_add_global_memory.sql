-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS vector;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gmem_kind') THEN
    CREATE TYPE gmem_kind AS ENUM ('fact','incident','medical','pattern','summary','faq','other');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS global_memories (
  id BIGSERIAL PRIMARY KEY,
  kind gmem_kind NOT NULL,
  content TEXT NOT NULL,
  labels TEXT[] NOT NULL DEFAULT '{}'::text[],
  source_session TEXT,
  embedding vector(1536),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gmem_kind ON global_memories(kind);
CREATE INDEX IF NOT EXISTS idx_gmem_labels ON global_memories USING GIN(labels);
CREATE INDEX IF NOT EXISTS idx_gmem_embed ON global_memories USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_gmem_embed;
DROP INDEX IF EXISTS idx_gmem_labels;
DROP INDEX IF EXISTS idx_gmem_kind;
DROP TABLE IF EXISTS global_memories;
DROP EXTENSION IF EXISTS vector;
-- +goose StatementEnd
