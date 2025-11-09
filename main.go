package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elgs/gojq"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"

	"lexisiq-intake-api/internal/ei"
	"lexisiq-intake-api/internal/learn"
)

var (
	ctx            = context.Background()
	oaClient       openai.Client
	db             *sql.DB
	mem            *learn.Global
	business       = "personal injury intake"
	sessionManager = &SessionManager{sessions: make(map[string]*Session)}
)

// ------------ Models ------------
type Message struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type ChatResponse struct {
	Message              string      `json:"message"`
	ConversationComplete bool        `json:"conversationComplete"`
	ClientProfile        interface{} `json:"clientProfile,omitempty"`
	SessionID            string      `json:"sessionId"`

	// NEW: expose model internals for debugging/telemetry
	InternalAssessment   interface{} `json:"Internal_Assessment,omitempty"`
	Detected             interface{} `json:"Detected,omitempty"`
	Stage                string      `json:"Stage,omitempty"`
	AskContact           string      `json:"Ask_Contact,omitempty"`
}

type Session struct {
	ID           string            `json:"id"`
	CreatedAt    time.Time         `json:"created_at"`
	LastActivity time.Time         `json:"last_activity"`
	Messages     []Message         `json:"messages"`
	ClientData   map[string]string `json:"client_data"`
}

type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
}

// ------------ Session helpers ------------
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (sm *SessionManager) CreateSession() (*Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	s := &Session{
		ID:           id,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Messages:     []Message{},
		ClientData:   make(map[string]string),
	}
	sm.mutex.Lock()
	sm.sessions[id] = s
	sm.mutex.Unlock()
	return s, nil
}

func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mutex.RLock()
	s, ok := sm.sessions[id]
	sm.mutex.RUnlock()
	if ok {
		sm.mutex.Lock()
		s.LastActivity = time.Now()
		sm.mutex.Unlock()
	}
	return s, ok
}

func (sm *SessionManager) AddMessage(id, role, content string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	s, ok := sm.sessions[id]
	if !ok {
		return fmt.Errorf("session not found")
	}
	s.Messages = append(s.Messages, Message{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	})
	s.LastActivity = time.Now()
	return nil
}

func (sm *SessionManager) UpdateClientData(id, key, value string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	s, ok := sm.sessions[id]
	if !ok {
		return fmt.Errorf("session not found")
	}
	if s.ClientData == nil {
		s.ClientData = make(map[string]string)
	}
	s.ClientData[key] = value
	s.LastActivity = time.Now()
	return nil
}

func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	expiration := time.Now().Add(-24 * time.Hour)
	for id, s := range sm.sessions {
		if s.LastActivity.Before(expiration) {
			delete(sm.sessions, id)
		}
	}
}

func startCleanupTask() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			sessionManager.CleanupExpiredSessions()
		}
	}()
}

// ------------ main ------------
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	_ = godotenv.Load()

	dsn := os.Getenv("NEON_DSN")
	openaiKey := os.Getenv("OPENAI_API_KEY")

	// --- DB (optional but preferred) ---
	if dsn == "" {
		log.Printf("NEON_DSN not set; starting without DB (memory-only mode)")
	} else {
		var derr error
		db, derr = sql.Open("pgx", dsn)
		if derr != nil {
			log.Printf("db open error; starting without DB: %v", derr)
		} else {
			ctxPing, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if perr := db.PingContext(ctxPing); perr != nil {
				log.Printf("db ping error; starting without DB: %v", perr)
				_ = db.Close()
				db = nil
			}
		}
	}

	// --- OpenAI ---
	if openaiKey == "" {
		log.Printf("OPENAI_API_KEY not set; requests to /chat will fail until you set it")
	} else {
		oaClient = openai.NewClient(option.WithAPIKey(openaiKey))
	}

	// --- Global memory only if DB is present ---
	if db != nil {
		mem = learn.NewGlobal(db)
	} else {
		mem = nil
	}

	// Start background session cleanup
	startCleanupTask()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /chat", HandleChat)

	log.Printf("API server starting on 0.0.0.0:%s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, enableCORS(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// ------------ HTTP/CORS helpers ------------
func enableCORS(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"https://californialawyermatch.com":  true,
		"http://localhost:8080":              true,
		"http://localhost:3003":              true,
		"https://lexisiq-intake-api.fly.dev": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

// ------------ DB helpers ------------
func ensureSession(sessionID string) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`INSERT INTO sessions (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, sessionID)
	return err
}

func saveMessage(sessionID, role, content string) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`INSERT INTO messages (session_id, role, content) VALUES ($1,$2,$3)`, sessionID, role, content)
	return err
}

// ------------ Early-contact + length helpers ------------
func explicitContactCue(s string) bool {
	s = strings.ToLower(s)
	pats := []string{
		`call me`, `can you call`, `contact me`, `reach me`,
		`my number is`, `phone is`, `email is`, `here'?s my email`,
		`how do i talk to`, `someone contact me`, `speak to a lawyer`,
		`urgent`, `asap`,
	}
	for _, p := range pats {
		if regexp.MustCompile(p).MatchString(s) {
			return true
		}
	}
	return false
}

func highDistress(llm any) bool {
	m, ok := llm.(map[string]interface{})
	if !ok {
		return false
	}
	ia, ok := m["Internal_Assessment"].(map[string]interface{})
	if !ok {
		return false
	}
	intensity, _ := ia["intensity"].(float64)
	emotion, _ := ia["emotion"].(string)
	emotion = strings.ToLower(emotion)
	if intensity >= 0.85 {
		switch emotion {
		case "anxiety", "fear", "sadness", "shame", "loneliness":
			return true
		}
	}
	return false
}

func enforceMaxSentences(s string, max int) string {
	if max <= 0 {
		return s
	}
	seps := []rune{'.', '?', '!'}
	var out []string
	start := 0
	for i, r := range s {
		if len(out) >= max {
			break
		}
		for _, sep := range seps {
			if r == sep {
				out = append(out, strings.TrimSpace(s[start:i+1]))
				start = i + 1
				break
			}
		}
	}
	if len(out) < max && start < len(s) {
		rest := strings.TrimSpace(s[start:])
		if rest != "" {
			out = append(out, rest)
		}
	}
	return strings.TrimSpace(strings.Join(out, " "))
}

func approxTruncateTokens(s string, target int) string {
	if target <= 0 {
		return s
	}
	limit := int(float64(target) * 1.3)
	words := strings.Fields(s)
	if len(words) <= limit {
		return s
	}
	return strings.Join(words[:limit], " ")
}

// ------------ /chat ------------
func HandleChat(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("parse form: %v", err)
		sendJSONError(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	log.Printf("Method=%s Path=%s Content-Type=%s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))

	if os.Getenv("OPENAI_API_KEY") == "" {
		sendJSONError(w, "LLM not configured (missing OPENAI_API_KEY)", http.StatusServiceUnavailable)
		return
	}

	// Get/Create session
	var session *Session
	var sessionID string
	if c, err := r.Cookie("session_id"); err == nil {
		if s, ok := sessionManager.GetSession(c.Value); ok {
			session = s
			sessionID = c.Value
		}
	}
	if session == nil {
		s, err := sessionManager.CreateSession()
		if err != nil {
			sendJSONError(w, "Error creating session", http.StatusInternalServerError)
			return
		}
		session = s
		sessionID = s.ID
		setSessionCookie(w, sessionID)
		if err := ensureSession(sessionID); err != nil {
			log.Printf("ensureSession: %v", err)
		}
	}

	// Inputs
	userMessage := strings.TrimSpace(r.FormValue("message"))
	accidentType := r.FormValue("accidentType")

	// Seed only if provided and no prior messages
	if accidentType != "" {
		_ = sessionManager.UpdateClientData(sessionID, "accidentType", accidentType)
		if len(session.Messages) == 0 && userMessage == "" {
			seed := fmt.Sprintf("I was involved in a %s.", accidentType)
			_ = sessionManager.AddMessage(sessionID, "user", seed)
			_ = saveMessage(sessionID, "user", seed)
		}
	}

	// Add user message if present
	if userMessage != "" {
		_ = sessionManager.AddMessage(sessionID, "user", userMessage)
		_ = saveMessage(sessionID, "user", userMessage)
	}

	// ---- Global memory retrieval (temporary system context) ----
	var injected bool
	if mem != nil && userMessage != "" {
		recs, _ := mem.Retrieve(ctx, userMessage, 8)
		if len(recs) > 0 {
			var b strings.Builder
			b.WriteString("Known relevant global context:\n")
			for _, rr := range recs {
				b.WriteString("- ")
				b.WriteString(rr.Content)
				b.WriteString("\n")
			}
			_ = sessionManager.AddMessage(sessionID, "system", b.String())
			injected = true
		}
	}

	// Generate assistant reply
	llmResponse, err := generateLLMResponse(session)
	if err != nil {
		if injected && len(session.Messages) > 0 && session.Messages[len(session.Messages)-1].Role == "system" {
			session.Messages = session.Messages[:len(session.Messages)-1]
		}
		log.Printf("generateLLMResponse: %v", err)
		sendJSONError(w, fmt.Sprintf("Error generating response: %v", err), http.StatusInternalServerError)
		return
	}

	// Remove temporary context
	if injected && len(session.Messages) > 0 && session.Messages[len(session.Messages)-1].Role == "system" {
		session.Messages = session.Messages[:len(session.Messages)-1]
	}

	// Extract client-visible message
	respMsg, err := llmResponse.Query("Client_Response")
	if err != nil {
		sendJSONError(w, "Malformed model response (Client_Response missing)", http.StatusInternalServerError)
		return
	}
	respStr, ok := respMsg.(string)
	if !ok {
		sendJSONError(w, "Model response type error", http.StatusInternalServerError)
		return
	}

	// EI tone prefix
	respStr = strings.TrimSpace(ei.TonePrefix(userMessage) + " " + respStr)

	// ---- Pull optional model internals for visibility ----
	var internalAssessment interface{}
	var detected interface{}
	var stageOut, askContactOut string

	if ia, _ := llmResponse.Query("Internal_Assessment"); ia != nil {
		internalAssessment = ia
		if m, ok := ia.(map[string]interface{}); ok {
			// stage
			if s, ok := m["stage"].(string); ok && s != "" {
				stageOut = s
			}
			// ask_contact (string OR bool)
			switch v := m["ask_contact"].(type) {
			case string:
				if v != "" {
					askContactOut = strings.ToLower(v)
				}
			case bool:
				if v {
					askContactOut = "true"
				} else {
					askContactOut = "false"
				}
			}
			// LLM-driven length constraints (optional)
			if v, ok := m["max_sentences"].(float64); ok && v > 0 {
				respStr = enforceMaxSentences(respStr, int(v))
			}
			if v, ok := m["target_tokens"].(float64); ok && v > 0 {
				respStr = approxTruncateTokens(respStr, int(v))
			}
		}
	}

	// Top-level fallbacks
	if st, _ := llmResponse.Query("Stage"); st != nil {
		if s, ok := st.(string); ok && s != "" {
			stageOut = s
		}
	}
	if ac, _ := llmResponse.Query("Ask_Contact"); ac != nil {
		switch v := ac.(type) {
		case string:
			if v != "" {
				askContactOut = strings.ToLower(v)
			}
		case bool:
			if v {
				askContactOut = "true"
			} else {
				askContactOut = "false"
			}
		}
	}
	if det, _ := llmResponse.Query("Detected"); det != nil {
		detected = det
	}

	// Contact request logic (model-driven)
	hasName := session.ClientData["name"] != ""
	hasEmail := session.ClientData["email"] != ""
	hasPhone := session.ClientData["phoneNumber"] != ""
	needContact := !(hasName && hasEmail && hasPhone)

	askContact := false
	if askContactOut != "" {
		askContact = (askContactOut == "true")
	}
	if askContact && needContact {
		respStr += " Before we continue, could you share your name, email, and phone so we can follow up if needed?"
	}

	// Persist assistant reply
	_ = sessionManager.AddMessage(sessionID, "assistant", respStr)
	_ = saveMessage(sessionID, "assistant", respStr)

	// Distill & store global learnings (user-agnostic)
	if mem != nil && userMessage != "" && respStr != "" {
		if err := mem.DistillAndStore(ctx, sessionID, userMessage, respStr); err != nil {
			log.Printf("learn.DistillAndStore error: %v", err)
		}
	}

	// Update any profile fields model inferred
	if cp, _ := llmResponse.Query("Client_Profile"); cp != nil {
		if m, ok := cp.(map[string]interface{}); ok {
			for k, v := range m {
				if sv, ok := v.(string); ok && sv != "" {
					_ = sessionManager.UpdateClientData(sessionID, k, sv)
				}
			}
		}
	}

	// Completion gate
	isComplete := false
	if flag, err := llmResponse.Query("Conversation_Complete"); err == nil {
		if s, ok := flag.(string); ok && s == "true" {
			hasName := session.ClientData["name"] != ""
			hasEmail := session.ClientData["email"] != ""
			hasPhone := session.ClientData["phoneNumber"] != ""
			isComplete = hasName && hasEmail && hasPhone
		}
	}

	// Respond
	resp := ChatResponse{
		Message:              respStr,
		ConversationComplete: isComplete,
		SessionID:            sessionID,
		InternalAssessment:   internalAssessment,
		Detected:             detected,
		Stage:                stageOut,
		AskContact:           askContactOut,
	}

	if cp, _ := llmResponse.Query("Client_Profile"); cp != nil {
		resp.ClientProfile = cp
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ------------ LLM ------------
func generateLLMResponse(session *Session) (*gojq.JQ, error) {
	var userQuery string
	if n := len(session.Messages); n > 0 {
		userQuery = session.Messages[n-1].Content
	}

	conversationContext := formatConversationHistory(session.Messages)
	if len(session.ClientData) > 0 {
		conversationContext += "\nExisting Client Information:\n"
		for k, v := range session.ClientData {
			if v != "" {
				conversationContext += fmt.Sprintf("%s: %s\n", k, v)
			}
		}
	}

	sys := fmt.Sprintf(`You are an empathetic %s intake assistant. Do not give legal advice.`, business) + `
LLM-only behavior (no templates, no regex heuristics):
- Derive empathy and wording from the user's own words. Avoid canned phrases.
- Detect emotion and severity semantically; scale empathy accordingly.
- Choose tone and response length dynamically; use tone_by_stage.json and length_rules.json as guidance, not hard limits.
- Ask exactly one concise follow-up question unless safety/clarity needs more.
- Decide contact timing yourself; set Ask_Contact="true" only when appropriate (readiness, next-step need, or user intent). Do not ask prematurely.
- Use the Detected object for semantic extraction (injuries, body regions, severity, mechanism, red_flags) from paraphrases (e.g., "shoulder's been throbbing", "can barely move", "back's been off since the crash").

Return ONLY one JSON object with these keys:
- "Client_Response" (string)
- "Internal_Assessment" (object; include: emotion, intensity [0..1], stage, max_sentences, target_tokens, ask_contact)
- "Conversation_Management" (object; optional stage hints)
- "Client_Profile" (object; optional inferred fields)
- "Case_Summary" (string)
- "Conversation_Complete" (string: "true" or "false")
- "Detected" (object; include semantic fields):
    - injuries: string[]                 // free-text, semantic (e.g., "neck stiffness", "shoulder throbbing")
    - body_regions: string[]             // normalized broad regions (e.g., "neck","shoulder","back","head")
    - pain_severity: number              // 0..1
    - mechanism: string[]                // e.g., "rear-end", "t-bone", "fall", "pedestrian"
    - red_flags: string[]                // e.g., "loss of consciousness","head strike","numbness","weakness","anticoagulants"
    - time_since_incident: string        // free-text (e.g., "last night","yesterday 10pm")
    - treatment_status: string           // e.g., "no care yet","saw ER","has PCP follow-up"

Rules:
- Output must be valid JSON (no markdown, no code fences).
- Always include "Detected" with all keys present; use empty arrays/strings when unknown.
- Ensure proper commas and no trailing commas.
`


	fullPrompt := fmt.Sprintf(
		"User Message:\n%s\n\nConversation Context:\n%s\n\nFollow the schema and rules strictly.",
		userQuery, conversationContext,
	)

	resp, err := oaClient.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: openai.ChatModelGPT4o,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(sys),
			openai.UserMessage(fullPrompt),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("OpenAI error: %v", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	content := strings.TrimSpace(resp.Choices[0].Message.Content)
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}
	content = repairJSON(content)

	jq, err := gojq.NewStringQuery(content)
	if err != nil {
		log.Printf("JSON repair failed; raw content:\n%s", content)
		return nil, fmt.Errorf("error parsing model JSON: %v", err)
	}
	return jq, nil
}

// ------------ Utilities ------------
func repairJSON(s string) string {
	reMissingComma := regexp.MustCompile(`("Case_Summary"\s*:\s*"(?:[^"\\]|\\.)*")\s*("Conversation_Complete")`)
	s = reMissingComma.ReplaceAllString(s, `$1, $2`)
	reTrailing := regexp.MustCompile(`,\s*([}\]])`)
	s = reTrailing.ReplaceAllString(s, `$1`)
	return strings.TrimSpace(s)
}

func formatConversationHistory(messages []Message) string {
	if len(messages) <= 1 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nConversation History:\n")
	for i := 0; i < len(messages)-1; i++ {
		m := messages[i]
		b.WriteString(fmt.Sprintf("[%s]: %s\n", m.Role, m.Content))
	}
	return b.String()
}

func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
