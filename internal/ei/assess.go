package ei

import (
	"regexp"
	"strings"
)

type Assessment struct {
	Emotion     string
	Intensity   string
	Incident    string
	RedFlags    []string
	TimeContext string
}

func Analyze(msg string) Assessment {
	u := strings.ToLower(msg)
	a := Assessment{}

	// emotion
	switch {
	case regexp.MustCompile(`\b(anxious|anxiety|worried|scared|fear|panic)\b`).MatchString(u):
		a.Emotion = "anxiety"
	case regexp.MustCompile(`\b(angry|mad|furious|upset|frustrated)\b`).MatchString(u):
		a.Emotion = "anger/frustration"
	case regexp.MustCompile(`\b(sad|depressed|down)\b`).MatchString(u):
		a.Emotion = "sadness"
	default:
		a.Emotion = "neutral"
	}

	// intensity
	switch {
	case regexp.MustCompile(`\b(severe|unbearable|extreme|can[’']?t sleep|can[’']?t move)\b`).MatchString(u):
		a.Intensity = "high"
	case regexp.MustCompile(`\b(moderate|pretty bad|quite|worse)\b`).MatchString(u):
		a.Intensity = "medium"
	default:
		a.Intensity = "low"
	}

	// incident
	switch {
	case regexp.MustCompile(`\brear[-\s]?end`).MatchString(u):
		a.Incident = "rear_end_auto"
	case regexp.MustCompile(`\b(hit[-\s]?and[-\s]?run)\b`).MatchString(u):
		a.Incident = "hit_and_run"
	case regexp.MustCompile(`\b(uber|lyft|ride[-\s]?share)\b`).MatchString(u):
		a.Incident = "rideshare"
	case regexp.MustCompile(`\bmotorcycle\b`).MatchString(u):
		a.Incident = "motorcycle"
	case regexp.MustCompile(`\b(bicycle|bike)\b`).MatchString(u):
		a.Incident = "bicycle"
	case regexp.MustCompile(`\b(pedestrian|crosswalk)\b`).MatchString(u):
		a.Incident = "pedestrian"
	case regexp.MustCompile(`\b(slip|trip|fall)\b`).MatchString(u):
		a.Incident = "slip_trip_fall"
	default:
		a.Incident = "unknown"
	}

	// red flags
	if regexp.MustCompile(`\b(head|concussion|lost consciousness|black(ed)? out)\b`).MatchString(u) {
		a.RedFlags = append(a.RedFlags, "possible_head_injury")
	}
	if regexp.MustCompile(`\b(numb|tingling|weakness|radiat)\b`).MatchString(u) {
		a.RedFlags = append(a.RedFlags, "neurologic_symptoms")
	}
	if regexp.MustCompile(`\b(chest pain|shortness of breath|difficulty breathing)\b`).MatchString(u) {
		a.RedFlags = append(a.RedFlags, "cardiopulmonary")
	}
	if regexp.MustCompile(`\b(fracture|broken|bone|deform)\b`).MatchString(u) {
		a.RedFlags = append(a.RedFlags, "possible_fracture")
	}

	// time context
	switch {
	case regexp.MustCompile(`\btoday\b`).MatchString(u):
		a.TimeContext = "today"
	case regexp.MustCompile(`\byesterday\b`).MatchString(u):
		a.TimeContext = "yesterday"
	case regexp.MustCompile(`\blast (night|week|month)\b`).MatchString(u):
		a.TimeContext = "recent"
	default:
		a.TimeContext = "unspecified"
	}

	return a
}

// TonePrefix returns a short empathy+guidance prefix to improve responses immediately.
func TonePrefix(msg string) string {
	a := Analyze(msg)

	var tone string
	switch a.Emotion {
	case "anxiety":
		tone = "I hear that you’re feeling anxious—let’s take this one step at a time."
	case "anger/frustration":
		tone = "I get why you’re frustrated—that sounds really upsetting."
	case "sadness":
		tone = "I’m sorry you’re going through this—it’s a lot to deal with."
	default:
		tone = "Thanks for sharing what happened."
	}

	var hint string
	switch a.Incident {
	case "rear_end_auto":
		hint = "Rear-end crashes often cause delayed neck pain—early evaluation helps."
	case "slip_trip_fall":
		hint = "For slips/trips, noting hazards and incident reports can help your claim."
	case "rideshare":
		hint = "With rideshare incidents, app trip logs help sort out insurance quickly."
	case "motorcycle":
		hint = "Motorcycle impacts can hide serious injuries—please monitor symptoms."
	case "bicycle":
		hint = "Bicycle crashes benefit from location details and lighting visibility."
	}

	if len(a.RedFlags) > 0 && hint == "" {
		hint = "Given your symptoms, consider timely medical attention if anything worsens."
	}

	if hint != "" {
		return tone + " " + hint
	}
	return tone
}
