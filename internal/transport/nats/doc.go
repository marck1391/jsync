// Package nats wraps connection bootstrap for both network roles defined in
// Fase 1: hub (embeds and owns a NATS server) and peer (connects out as a
// Leaf Node to a hub's broker). It also owns the jsync.* subject naming
// scheme (control, stream, events, status) and JetStream stream/consumer
// setup shared by the sender and receiver pipelines (Fase 2, Fase 5).
package nats
