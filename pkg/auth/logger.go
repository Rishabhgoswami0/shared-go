package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LogEvent structure for structured JSON auth logs
type AuthLogEvent struct {
	Timestamp string                 `json:"timestamp"`
	Event     string                 `json:"event"`
	Reason    string                 `json:"reason,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// LogEvent prints a standardized JSON log for auth events
func LogEvent(event string, reason string, details map[string]interface{}) {
	logEntry := AuthLogEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     event,
		Reason:    reason,
		Details:   details,
	}

	bytes, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"event":"auth_log_encoder_error","error":%q}`+"\n", err.Error())
		return
	}

	fmt.Println(string(bytes))
}
