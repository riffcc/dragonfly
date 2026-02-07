use tokio::sync::broadcast;
use tracing::{info, warn};

// Event types that can be published
#[derive(Debug, Clone)]
pub enum Event {
    MachineDiscovered(String),
    MachineUpdated(String),
    MachineDeleted(String),
}

// Event manager for publishing SSE events
pub struct EventManager {
    tx: broadcast::Sender<String>,
}

impl EventManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }

    // Create a new subscription to events
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    // Publish an event, returning Result to handle errors
    pub fn send(&self, message: String) -> Result<usize, broadcast::error::SendError<String>> {
        let receivers = self.tx.receiver_count();

        // Only attempt to send if we have receivers to avoid log spam
        if receivers > 0 {
            match self.tx.send(message.clone()) {
                Ok(n) => {
                    info!("Event sent to {} receivers: {}", n, message);
                    Ok(n)
                }
                Err(e) => {
                    warn!("Failed to send event: {}", e);
                    Err(e)
                }
            }
        } else {
            // Create a more descriptive error when there are no receivers
            warn!("No receivers for event: {}", message);
            Err(broadcast::error::SendError(message))
        }
    }

    // Get the current receiver count
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventManager {
    fn default() -> Self {
        Self::new()
    }
}

// Make EventManager safe to clone by wrapping in Arc
impl Clone for EventManager {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_manager_new() {
        let em = EventManager::new();
        assert_eq!(em.receiver_count(), 0);
    }

    #[test]
    fn test_event_manager_default() {
        let em = EventManager::default();
        assert_eq!(em.receiver_count(), 0);
    }

    #[test]
    fn test_event_manager_subscribe_increases_count() {
        let em = EventManager::new();
        assert_eq!(em.receiver_count(), 0);

        let _rx1 = em.subscribe();
        assert_eq!(em.receiver_count(), 1);

        let _rx2 = em.subscribe();
        assert_eq!(em.receiver_count(), 2);
    }

    #[test]
    fn test_event_manager_send_without_receivers_fails() {
        let em = EventManager::new();
        let result = em.send("test_message".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_event_manager_send_with_receiver_succeeds() {
        let em = EventManager::new();
        let _rx = em.subscribe();

        let result = em.send("test_message".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // One receiver got the message
    }

    #[tokio::test]
    async fn test_event_manager_receive_message() {
        let em = EventManager::new();
        let mut rx = em.subscribe();

        // Send a message
        let _ = em.send("hello".to_string());

        // Receive it
        let received = rx.recv().await;
        assert!(received.is_ok());
        assert_eq!(received.unwrap(), "hello");
    }

    #[test]
    fn test_event_manager_clone() {
        let em1 = EventManager::new();
        let em2 = em1.clone();

        // Both should share the same channel
        let _rx = em1.subscribe();
        assert_eq!(em2.receiver_count(), 1);
    }

    #[test]
    fn test_event_enum_debug() {
        // Test that Event enum implements Debug
        let event = Event::MachineDiscovered("test-uuid".to_string());
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("MachineDiscovered"));
        assert!(debug_str.contains("test-uuid"));
    }

    #[test]
    fn test_event_enum_variants() {
        let discovered = Event::MachineDiscovered("id1".to_string());
        let updated = Event::MachineUpdated("id2".to_string());
        let deleted = Event::MachineDeleted("id3".to_string());

        // Test clone
        let discovered_clone = discovered.clone();
        assert!(matches!(discovered_clone, Event::MachineDiscovered(id) if id == "id1"));
        assert!(matches!(updated, Event::MachineUpdated(id) if id == "id2"));
        assert!(matches!(deleted, Event::MachineDeleted(id) if id == "id3"));
    }
}
