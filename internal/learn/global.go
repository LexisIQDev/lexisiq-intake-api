package learn

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Global struct {
	DB     *sql.DB
	apiKey string
	httpc  *http.Client
}

func NewGlobal(db *sql.DB) *Global {
	return &Global{
		DB:     db,
		apiKey: os.Getenv("OPENAI_API_KEY"),
		httpc:  &http.Client{Timeout: 15 * time.Second},
	}
}

var piiRe = regexp.MustCompile(`(?i)(\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b|\b\d{10}\b|\(\d{3}\)\s?\d{3}[-.\s]?\d{4}|\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b|[\w\.-]+@[\w\.-]+\.\w+)`)

func RedactPII(s string) string {
	s = strings.TrimSpace(s)
	return piiRe.ReplaceAllString(s, "[REDACTED]")
}

type embReq struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}
type embResp struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (g *Global) Embed(ctx context.Context, text string) ([]float32, error) {
	if g.apiKey == "" {
		return nil, errors.New("missing OPENAI_API_KEY")
	}
	body, _ := json.Marshal(embReq{
		Model: "text-embedding-3-small",
		Input: []string{text},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := g.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("embedding request failed")
	}
	var out embResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Data) == 0 {
		return nil, errors.New("no embedding returned")
	}
	return out.Data[0].Embedding, nil
}

func (g *Global) AddMemory(ctx context.Context, kind, content string, labels []string, sourceSession string) error {
	content = RedactPII(strings.TrimSpace(content))
	emb, err := g.Embed(ctx, content)
	if err != nil {
		return err
	}
	embJSON, _ := json.Marshal(emb)
	_, err = g.DB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS global_memories (
			id BIGSERIAL PRIMARY KEY,
			kind TEXT NOT NULL,
			content TEXT NOT NULL,
			labels TEXT[] NOT NULL DEFAULT '{}',
			source_session TEXT NOT NULL,
			embedding JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	if err != nil {
		return err
	}
	_, err = g.DB.ExecContext(ctx, `
		INSERT INTO global_memories (kind, content, labels, source_session, embedding)
		VALUES ($1,$2,$3,$4,$5::jsonb)
	`, kind, content, pgArray(labels), sourceSession, string(embJSON))
	return err
}

type Retrieved struct {
	Content string
	Kind    string
	Score   float64
}

func (g *Global) Retrieve(ctx context.Context, query string, k int) ([]Retrieved, error) {
	if k <= 0 {
		k = 5
	}
	rows, err := g.DB.QueryContext(ctx, `
		SELECT content, kind
		FROM global_memories
		ORDER BY created_at DESC
		LIMIT $1
	`, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Retrieved
	for rows.Next() {
		var c, kind string
		if err := rows.Scan(&c, &kind); err != nil {
			return nil, err
		}
		out = append(out, Retrieved{Content: c, Kind: kind, Score: 0})
	}
	return out, rows.Err()
}

func pgArray(ss []string) any {
	if len(ss) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteString("{")
	for i, s := range ss {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
	}
	b.WriteString("}")
	return b.String()
}
