package ei

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type Emotion string
type Stage string

type Matrix struct {
	Emotions []string                  `json:"emotions"`
	Strategy map[string]map[string]any `json:"strategy"`
}

type ToneByStage struct {
	Stages []string           `json:"stages"`
	Tone   map[string][]string `json:"tone"`
}

type LengthRule struct {
	When         string `json:"when"`
	TargetTokens int    `json:"target_tokens"`
	MaxSentences int    `json:"max_sentences"`
}

type LengthRules struct {
	Rules    []LengthRule `json:"rules"`
	Defaults LengthRule   `json:"defaults"`
}

type Detection struct {
	Emotion Emotion `json:"emotion"`
	Score   float64 `json:"score"`
	Stage   Stage   `json:"stage"`
}

type Plan struct {
	Emotion      Emotion   `json:"emotion"`
	EmpathyLevel int       `json:"empathy_level"` // 0..4
	EmpathyMode  string    `json:"empathy_mode"`  // neutral|direct|supportive|validating|reverse-factual
	TonePreset   []string  `json:"tone_preset"`
	TargetTokens int       `json:"target_tokens"`
	MaxSentences int       `json:"max_sentences"`
	WhenTag      string    `json:"when_tag"`
	CreatedAt    time.Time `json:"created_at"`
}

type AccidentTypes struct {
	Types []string `json:"types"`
}

type Planner struct {
	matrix        Matrix
	tones         ToneByStage
	length        LengthRules
	accidentTypes AccidentTypes
}

func LoadPlanner() (*Planner, error) {
	mx, err := readJSON[Matrix]("config/ei_matrix.json")
	if err != nil {
		return nil, err
	}
	tone, err := readJSON[ToneByStage]("config/tone_by_stage.json")
	if err != nil {
		return nil, err
	}
	lr, err := readJSON[LengthRules]("config/length_rules.json")
	if err != nil {
		return nil, err
	}
	// Optional: load accident types for sanity check
	at, _ := readJSON[AccidentTypes]("config/accident_types.json")

	p := &Planner{matrix: mx, tones: tone, length: lr, accidentTypes: at}
	if err := p.EnsureReady(); err != nil {
		return nil, err
	}
	return p, nil
}

func readJSON[T any](p string) (T, error) {
	var z T
	b, err := os.ReadFile(p)
	if err != nil {
		return z, err
	}
	if err := json.Unmarshal(b, &z); err != nil {
		return z, err
	}
	return z, nil
}

func (p *Planner) ClassifyWhen(userText string, stage Stage) string {
	lt := strings.ToLower(userText)

	switch {
	case stage == "closure":
		return "closure_summary"
	case stage == "qualification":
		return "explain_next_step"
	case regexp.MustCompile(`(?i)\b(suicid|panic|terrified|cry|hurt so bad|can't cope|overwhelmed)\b`).MatchString(lt):
		return "distress_disclosed"
	case regexp.MustCompile(`(?i)\b(name|email|phone|date|address|dob|policy|claim|police report|report number)\b`).MatchString(lt):
		return "collecting_fact"
	case regexp.MustCompile(`(?i)\b(er|emergency room|urgent care|hospital|doctor|mri|x-?ray|therapy|treatment)\b`).MatchString(lt):
		return "medical_context"
	default:
		return "default"
	}
}

// Backward-compatible Plan() keeps existing call sites working.
func (p *Planner) Plan(d Detection) (Plan, error) {
	return p.PlanWithText(d, "")
}

// New variant that uses userText for better length/tone selection.
func (p *Planner) PlanWithText(d Detection, userText string) (Plan, error) {
	s := p.matrix.Strategy[string(d.Emotion)]
	if s == nil {
		s = p.matrix.Strategy["default"]
	}

	empathy := intFrom(s["default_empathy"], 2)
	mode := firstStringFromSlice(s["modes"], "neutral")

	tone := p.tones.Tone[string(d.Stage)]
	if tone == nil {
		tone = []string{"professional", "clear"}
	}

	when := p.ClassifyWhen(userText, d.Stage)
	target := p.length.Defaults.TargetTokens
	maxS := p.length.Defaults.MaxSentences

	for _, r := range p.length.Rules {
		if strings.EqualFold(r.When, when) {
			target = r.TargetTokens
			maxS = r.MaxSentences
			break
		}
	}

	return Plan{
		Emotion:      d.Emotion,
		EmpathyLevel: clamp(empathy+adjustBySeverity(d.Score), 0, 4),
		EmpathyMode:  mode,
		TonePreset:   tone,
		TargetTokens: target,
		MaxSentences: maxS,
		WhenTag:      when,
		CreatedAt:    time.Now(),
	}, nil
}

func adjustBySeverity(score float64) int {
	switch {
	case score >= 0.85:
		return 2
	case score >= 0.6:
		return 1
	case score <= 0.25:
		return -1
	default:
		return 0
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func intFrom(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		return def
	}
}

func firstStringFromSlice(v any, def string) string {
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return def
	}
	if s, ok := a[0].(string); ok {
		return s
	}
	return def
}

// GuessStage is a simple fallback if the frontend doesn't send a stage.
func GuessStage(history []string) Stage {
	if len(history) <= 1 {
		return "opening"
	}
	for _, h := range history {
		if strings.Contains(strings.ToLower(h), "consent") {
			return "disclosure"
		}
	}
	return "discovery"
}

func (p Plan) SystemDirectives(business string) string {
	return fmt.Sprintf(
		`You are an intake assistant for %s.
Follow these constraints:
- Empathy level: %d (0=neutral, 4=high). Mode: %s.
- Tone: %s.
- Keep to <= %d sentences and ~%d tokens unless safety or clarity require more.
- Never provide legal advice; gather facts, reassure, and explain next steps briefly.`,
		business, p.EmpathyLevel, p.EmpathyMode, strings.Join(p.TonePreset, ", "),
		p.MaxSentences, p.TargetTokens,
	)
}

// EnsureReady validates loaded configs (EI matrix 25+ emotions; optional PI types exist).
func (p *Planner) EnsureReady() error {
	if len(p.matrix.Emotions) < 25 {
		return errors.New("ei_matrix.json must contain >=25 emotions")
	}
	if p.tones.Tone == nil || len(p.tones.Tone) == 0 {
		return errors.New("tone_by_stage.json tone map missing")
	}
	if p.length.Defaults.MaxSentences == 0 || p.length.Defaults.TargetTokens == 0 {
		return errors.New("length_rules.json defaults missing")
	}
	// Accident types optional, but if present must not be empty.
	if p.accidentTypes.Types != nil && len(p.accidentTypes.Types) == 0 {
		return errors.New("accident_types.json present but empty types")
	}
	return nil
}

func Validate() error {
	_, err := LoadPlanner()
	if err != nil {
		return errors.New("planner failed to load: " + err.Error())
	}
	return nil
}

// ===== Smart sanitization =====

var (
	reLeadingFirstPerson = regexp.MustCompile(`(?i)^\s*(i'm|i am|i was|i have|i've|i had|i|my)\b`)
	reHealthIncident     = regexp.MustCompile(`(?i)\b(doctor|hospital|er|urgent care|insurance|policy|claim|crash|accident|collision|fall|balcony|injur(?:y|ies)|pain|ambulance|police report|therapy|treatment|x-?ray|mri)\b`)
	reSeenDoctorNeg      = regexp.MustCompile(`(?i)\b(i\s+have\s+not|i\s+haven't)\s+seen\s+a\s+doctor\b`)
	reSeenDoctorPos      = regexp.MustCompile(`(?i)\b(i\s+have\s+seen|i\s+saw|i'?ve\s+seen)\s+a\s+doctor\b`)
	reNoInsurance        = regexp.MustCompile(`(?i)\b(i\s+do\s+not\s+have|i\s+don't\s+have)\s+(health\s+)?insurance\b`)
	reInvolvedCrash      = regexp.MustCompile(`(?i)\b(i\s+was\s+in|i\s+was\s+involved\s+in)\s+(a\s+)?(crash|accident|collision|fall)\b`)
	reFellOffBalcony     = regexp.MustCompile(`(?i)\b(i\s+fell\s+off\s+(the\s+)?balcony)\b`)
	reCantSleepAnx       = regexp.MustCompile(`(?i)\b(i\s+can'?t\s+sleep).*(anxious|anxiety)|\b(i'?m\s+very\s+anxious)\b`)
	rePhonePolicyInfo    = regexp.MustCompile(`(?i)\b(my\s+phone\s+is|my\s+policy\s+number\s+is|i\s+don'?t\s+have\s+the\s+policy)\b`)
)

func SmartSanitizeAssistant(msg string) string {
	orig := strings.TrimSpace(msg)
	lower := strings.ToLower(orig)

	allowPrefixes := []string{
		"i'm sorry", "i am sorry", "i’m sorry",
		"i understand", "i completely understand", "i totally understand",
		"i can understand", "i hear you", "i’m here", "i am here",
	}
	for _, p := range allowPrefixes {
		if strings.HasPrefix(lower, p) {
			return orig
		}
	}

	erRE := regexp.MustCompile(`(?i)\b(i\s+(went|was|have\s+been|got)\s+to\s+(the\s+)?(er|e\.r\.|emergency\s+room|hospital|urgent\s+care))\b`)
	if erRE.MatchString(lower) {
		return "You went to the ER—thanks for sharing. What did they tell you, and did they recommend any follow-up?"
	}

	fpHealth := []string{
		"i haven't seen a doctor", "i have not seen a doctor",
		"i saw a doctor", "i visited a doctor", "i've been to a doctor",
		"i don't have insurance", "i do not have insurance",
		"i was in the crash", "i got injured", "i am injured", "i was hurt",
		"i'm injured", "i'm hurt",
	}
	for _, phrase := range fpHealth {
		if strings.Contains(lower, phrase) {
			return "Understood—have you been able to see a doctor yet, and do you currently have health insurance?"
		}
	}

	if regexp.MustCompile(`(?i)\bi can'?t sleep\b`).MatchString(lower) &&
		(regexp.MustCompile(`(?i)\b(i'?m|i am)\s+very\s+anxious\b`).MatchString(lower) ||
			strings.Contains(lower, "very anxious")) {
		return "It makes sense you’re having trouble sleeping and feeling anxious after this. Would it help to talk about what’s keeping you up and anything you’ve already tried?"
	}

	if strings.HasPrefix(lower, "i ") || strings.HasPrefix(lower, "i'm ") ||
		strings.HasPrefix(lower, "i’ve ") || strings.HasPrefix(lower, "i have ") {
		return "Thanks for sharing—can you tell me a bit more about what happened and how you’re feeling now?"
	}

	return FixSelfReference(orig)
}

func ensurePunct(newText, original string) string {
	newText = strings.TrimSpace(newText)
	if newText == "" {
		return original
	}
	if strings.HasSuffix(strings.TrimSpace(original), "?") && !strings.HasSuffix(newText, "?") {
		return newText + "?"
	}
	if strings.HasSuffix(strings.TrimSpace(original), "!") && !strings.HasSuffix(newText, "!") {
		return newText + "!"
	}
	if strings.HasSuffix(newText, ".") || strings.HasSuffix(newText, "?") || strings.HasSuffix(newText, "!") {
		return newText
	}
	return newText + "."
}

func extractOneOf(s string, opts []string) string {
	for _, o := range opts {
		if strings.Contains(s, o) {
			return o
		}
	}
	return ""
}

func flipFirstPersonToSecondPerson(s string) string {
	repls := []struct {
		re   *regexp.Regexp
		with string
	}{
		{regexp.MustCompile(`(?i)\bI am\b`), "You are"},
		{regexp.MustCompile(`(?i)\bI'm\b`), "You're"},
		{regexp.MustCompile(`(?i)\bI was\b`), "You were"},
		{regexp.MustCompile(`(?i)\bI were\b`), "You were"},
		{regexp.MustCompile(`(?i)\bI have\b`), "You have"},
		{regexp.MustCompile(`(?i)\bI've\b`), "You have"},
		{regexp.MustCompile(`(?i)\bI had\b`), "You had"},
		{regexp.MustCompile(`(?i)\bI don't\b`), "You don't"},
		{regexp.MustCompile(`(?i)\bI do not\b`), "You do not"},
		{regexp.MustCompile(`(?i)\bI can't\b`), "You can't"},
		{regexp.MustCompile(`(?i)\bI cannot\b`), "You cannot"},
		{regexp.MustCompile(`(?i)\bI\b`), "You"},
		{regexp.MustCompile(`(?i)\bmy\b`), "your"},
		{regexp.MustCompile(`(?i)\bMy\b`), "Your"},
		{regexp.MustCompile(`(?i)\bme\b`), "you"},
	}
	out := s
	for _, r := range repls {
		out = r.re.ReplaceAllString(out, r.with)
	}
	out = strings.ReplaceAll(out, " ,", ",")
	out = strings.ReplaceAll(out, " .", ".")
	out = strings.TrimSpace(out)
	return ensurePunct(out, s)
}

// ===== Legacy fallback =====

func FixSelfReference(msg string) string {
	lower := strings.ToLower(msg)

	firstPersonTriggers := []string{
		"i haven't seen a doctor", "i have not seen a doctor",
		"i saw a doctor", "i visited a doctor", "i've been to a doctor",
		"i don't have insurance", "i do not have insurance",
		"i was in the crash", "i got injured", "i am injured", "i was hurt",
		"i’m hurt", "i'm injured", "i was driving", "i was hit",
	}
	for _, phrase := range firstPersonTriggers {
		if strings.Contains(lower, phrase) {
			return "You haven’t seen a doctor yet, is that right?"
		}
	}

	if strings.HasPrefix(lower, "i ") || strings.HasPrefix(lower, "i'm ") ||
		strings.HasPrefix(lower, "i’ve ") || strings.HasPrefix(lower, "i have ") {
		return "Can you tell me a bit more about your situation?"
	}
	return msg
}
