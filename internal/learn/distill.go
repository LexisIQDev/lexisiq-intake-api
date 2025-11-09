package learn

import (
	"context"
	"regexp"
	"strings"
)

func (g *Global) DistillAndStore(ctx context.Context, sessionID, userMsg, assistantMsg string) error {
	u := strings.ToLower(userMsg)
	var patterns []string

	if regexp.MustCompile(`\brear[-\s]?end(ed|ing)?\b`).MatchString(u) {
		patterns = append(patterns, "Rear-end collisions often produce neck stiffness and delayed pain onset (whiplash).")
	}
	if regexp.MustCompile(`\bhit[-\s]?and[-\s]?run\b`).MatchString(u) {
		patterns = append(patterns, "Hit-and-run victims benefit from contemporaneous report numbers and nearby camera checks.")
	}
	if regexp.MustCompile(`\bslip|trip|fall\b`).MatchString(u) {
		patterns = append(patterns, "Slip/trip incidents hinge on hazard notice, cleanup logs, and incident reports.")
	}
	if regexp.MustCompile(`\buber|lyft|ride[-\s]?share\b`).MatchString(u) {
		patterns = append(patterns, "Rideshare crashes require app trip logs and which party's insurer is primary.")
	}
	if regexp.MustCompile(`\bmotorcycle\b`).MatchString(u) {
		patterns = append(patterns, "Motorcycle incidents often involve visibility disputes; helmet/gear details matter.")
	}
	if regexp.MustCompile(`\bbicycle|bike\b`).MatchString(u) {
		patterns = append(patterns, "Bicycle impacts: lane position, lighting, and post-crash symptoms are key.")
	}
	if regexp.MustCompile(`\bneck|back|shoulder|knee|headache|concussion|stiff(ness)?\b`).MatchString(u) {
		patterns = append(patterns, "Soft-tissue complaints may escalate after 24–72h; early evaluation helps.")
	}
	if regexp.MustCompile(`\bambulance|er|urgent care|x-?ray|mri\b`).MatchString(u) {
		patterns = append(patterns, "Existing diagnostics should be gathered for continuity of care and billing.")
	}
	if regexp.MustCompile(`\b(last|yesterday|today|friday|saturday|sunday|monday|tuesday|wednesday|thursday)\b`).MatchString(u) {
		patterns = append(patterns, "Precise date/time anchors improve claim chronology and witness recall.")
	}
	if regexp.MustCompile(`\binsurance|claim\b`).MatchString(u) {
		patterns = append(patterns, "Record adjuster contacts and claim numbers early to avoid delays.")
	}

	seen := map[string]bool{}
	for _, p := range patterns {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		_ = g.AddMemory(ctx, "pattern", p, []string{"global"}, sessionID)
	}
	return nil
}
