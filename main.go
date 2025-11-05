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
	"github.com/joho/godotenv"

	_ "github.com/jackc/pgx/v5/stdlib" // Postgres driver (Neon-compatible)

	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

var (
	ctx            = context.Background()
	oaClient       openai.Client
	db             *sql.DB
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

// ------------ Init (env, OpenAI, DB) ------------
func init() {
	_ = godotenv.Load(".env")

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		log.Println("WARNING: OPENAI_API_KEY is not set")
	}
	oaClient = openai.NewClient(option.WithAPIKey(apiKey))

	dsn := os.Getenv("NEON_DSN")
	if dsn == "" {
		log.Println("WARNING: NEON_DSN is not set (DB persistence disabled)")
	} else {
		var err error
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		if err := db.Ping(); err != nil {
			log.Fatalf("ping db: %v", err)
		}
	}

	startCleanupTask()
}

// ------------ main ------------
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /chat", HandleChat)

	log.Printf("API server starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, enableCORS(mux)))
}

// ------------ HTTP/CORS helpers ------------
func enableCORS(next http.Handler) http.Handler {
	// Allow your prod domain(s) + localhost dev
	allowed := map[string]bool{
		"https://californialawyermatch.com": true,
		"http://localhost:8080":             true,
		"http://localhost:3003":             true,
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

// ------------ /chat ------------
func HandleChat(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("parse form: %v", err)
		sendJSONError(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	log.Printf("Method=%s Path=%s Content-Type=%s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))

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

	// Inputs: chat message + OPTIONAL first-intake param
	userMessage := r.FormValue("message")
	accidentType := r.FormValue("accidentType") // optional seed; everything else is chat-only now

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

	// Generate assistant reply
	llmResponse, err := generateLLMResponse(session)
	if err != nil {
		log.Printf("generateLLMResponse: %v", err)
		sendJSONError(w, fmt.Sprintf("Error generating response: %v", err), http.StatusInternalServerError)
		return
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

	// Persist assistant reply
	_ = sessionManager.AddMessage(sessionID, "assistant", respStr)
	_ = saveMessage(sessionID, "assistant", respStr)

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

	// Completion gate: require name/email/phone in ClientData, but acquired via chat now
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

	// Conversation and inline client data
	conversationContext := formatConversationHistory(session.Messages)
	if len(session.ClientData) > 0 {
		conversationContext += "\nExisting Client Information:\n"
		for k, v := range session.ClientData {
			if v != "" {
				conversationContext += fmt.Sprintf("%s: %s\n", k, v)
			}
		}
	}

	sys := fmt.Sprintf(`You are an empathetic %s intake assistant. Ask brief, focused questions to gather details, but do not give legal advice.`, business) + `
Tone & EI rules:
- Be warm, validating, and professional.
- Reflect the user's emotion in 1 short phrase before your follow-up question (e.g., "I’m sorry that was so stressful.").
- Keep replies concise (2–3 sentences), then exactly one follow-up question.
- Never offer medical or legal conclusions; only guide intake.

IMPORTANT: Always capture the client's full name, email, and phone during the flow.
`

	jsonInstruction := `
Return ONLY a single JSON object with these keys:
- "Client_Response" (string)
- "Internal_Assessment" (object)
- "Conversation_Management" (object)
- "Client_Profile" (object)
- "Case_Summary" (string)
- "Conversation_Complete" (string: "true" or "false")

Rules:
- Respond ONLY with valid JSON (no markdown, no code fences).
- Ensure commas between all keys. Do not leave trailing commas.
`

	fullPrompt := fmt.Sprintf(
		"User Message:\n%s\n\nConversation Context:\n%s\n\nFollow the JSON schema and rules strictly.",
		userQuery, conversationContext,
	)

	resp, err := oaClient.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: openai.ChatModelGPT4o,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(sys + "\n\n" + jsonInstruction),
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
	// fix missing comma between Case_Summary and Conversation_Complete
	reMissingComma := regexp.MustCompile(`("Case_Summary"\s*:\s*"(?:[^"\\]|\\.)*")\s*("Conversation_Complete")`)
	s = reMissingComma.ReplaceAllString(s, `$1, $2`)
	// strip trailing commas before } or ]
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
