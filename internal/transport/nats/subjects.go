package nats

import "fmt"

// subjectPrefix roots the whole jsync.* subject hierarchy shared by
// Fase 1 (control), Fase 2 (stream/status), and Fase 5 (events).
const subjectPrefix = "jsync"

// ActionHandshake is the control action Fase 1's challenge-response uses.
const ActionHandshake = "handshake"

// ControlSubject is where a Fase 1 Request for targetMachineID's action is
// published: jsync.control.<target_machine_id>.<action>.
func ControlSubject(targetMachineID, action string) string {
	return fmt.Sprintf("%s.control.%s.%s", subjectPrefix, targetMachineID, action)
}

// StreamSubject is the JetStream subject a Fase 2 transfer publishes chunks
// to once Fase 1 hands back sessionID.
func StreamSubject(sessionID string) string {
	return fmt.Sprintf("%s.stream.%s", subjectPrefix, sessionID)
}

// EventsSubject is the Fase 5 watcher's bidirectional event subject for a
// session — both peers in a watcher session publish and subscribe here.
func EventsSubject(sessionID string) string {
	return fmt.Sprintf("%s.events.%s", subjectPrefix, sessionID)
}

// StatusSubject is where a receiver reports transfer progress for
// sessionID (Fase 2 §5), consumed by internal/progress.
func StatusSubject(sessionID string) string {
	return fmt.Sprintf("%s.status.%s", subjectPrefix, sessionID)
}
