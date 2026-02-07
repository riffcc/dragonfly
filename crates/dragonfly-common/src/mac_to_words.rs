use std::num::ParseIntError;
use uuid::Uuid;

// Full BIP39 wordlist (2048 words)
include!("bip39_wordlist.rs");

/// Generates a deterministic UUID v5 from a MAC address
///
/// Uses the DNS namespace and MAC address bytes to create a consistent
/// UUID that will be the same for the same MAC address across all systems.
///
/// # Arguments
///
/// * `mac` - MAC address in the format "xx:xx:xx:xx:xx:xx"
///
/// # Returns
///
/// A UUID v5 derived from the MAC address
pub fn mac_to_uuid(mac: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, mac.as_bytes())
}

/// Converts a MAC address to a memorable name using BIP39 words
///
/// # Arguments
///
/// * `mac` - MAC address in the format "xx:xx:xx:xx:xx:xx"
///
/// # Returns
///
/// A string with the memorable name or an error if parsing fails
pub fn mac_to_words(mac: &str) -> Result<String, ParseIntError> {
    // Remove colons and convert to a 48-bit integer
    let clean_mac = mac.replace(":", "");
    let mac_int = u64::from_str_radix(&clean_mac, 16)?;

    // Each word in BIP39 encodes 11 bits (2048 = 2^11)
    // We'll use 4 words, which gives us 44 bits of entropy
    // This is slightly less than the full 48 bits but still more than enough
    // for our use case of unique identification

    // We're using the last 44 bits of the MAC address
    // This emphasizes the unique device-specific portion rather than the
    // manufacturer-specific OUI portion at the beginning

    // Extract 11 bits for each word index, focusing on the last 44 bits
    let word1_idx = ((mac_int >> 33) & 0x7FF) as usize; // bits 33-43 (last 44 bits, first 11)
    let word2_idx = ((mac_int >> 22) & 0x7FF) as usize; // bits 22-32 (last 44 bits, second 11)
    let word3_idx = ((mac_int >> 11) & 0x7FF) as usize; // bits 11-21 (last 44 bits, third 11)
    let word4_idx = (mac_int & 0x7FF) as usize; // bits 0-10 (last 44 bits, fourth 11)

    // Get the words
    let word1 = WORDLIST[word1_idx % WORDLIST.len()];
    let word2 = WORDLIST[word2_idx % WORDLIST.len()];
    let word3 = WORDLIST[word3_idx % WORDLIST.len()];
    let word4 = WORDLIST[word4_idx % WORDLIST.len()];

    // Capitalize the first letter of each word
    let word1 = capitalize(word1);
    let word2 = capitalize(word2);
    let word3 = capitalize(word3);
    let word4 = capitalize(word4);

    // Combine into a memorable name
    Ok(format!("{}{}{}{}", word1, word2, word3, word4))
}

/// Converts a MAC address to a memorable name using BIP39 words, with a fallback
///
/// This version is safer to use since it won't fail, providing a fallback
/// if parsing fails.
///
/// # Arguments
///
/// * `mac` - MAC address in the format "xx:xx:xx:xx:xx:xx"
///
/// # Returns
///
/// A string with the memorable name
pub fn mac_to_words_safe(mac: &str) -> String {
    match mac_to_words(mac) {
        Ok(name) => name,
        Err(_) => format!(
            "Machine-{}",
            mac.replace(":", "").chars().take(8).collect::<String>()
        ),
    }
}

// Helper function to capitalize the first letter of a word
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_to_words() {
        let mac = "04:7c:16:eb:74:ed";
        let result = mac_to_words(mac).unwrap();

        // Check if we got four capitalized words
        let word_count = result.chars().filter(|c| c.is_uppercase()).count();
        assert_eq!(word_count, 4);

        println!("MAC {} converted to: {}", mac, result);

        // Verify two different MACs give different names
        let mac2 = "04:7c:16:eb:74:ee"; // Just one bit different in the last byte
        let result2 = mac_to_words(mac2).unwrap();
        assert_ne!(result, result2);
        println!("MAC {} converted to: {}", mac2, result2);

        // Verify MACs with the same OUI but different device IDs get different names
        let mac4 = "04:7c:16:eb:75:ed"; // Different middle byte
        let result4 = mac_to_words(mac4).unwrap();
        assert_ne!(result, result4);
        println!(
            "MAC {} (different device ID) converted to: {}",
            mac4, result4
        );
    }

    #[test]
    fn test_mac_to_words_safe() {
        let mac = "04:7c:16:eb:74:ed";
        let result = mac_to_words_safe(mac);

        // Check if we got a name
        assert!(result.len() > 0);

        println!("MAC {} safely converted to: {}", mac, result);

        // Test with invalid MAC
        let invalid_mac = "invalid";
        let fallback = mac_to_words_safe(invalid_mac);
        assert!(fallback.starts_with("Machine-"));
    }

    #[test]
    fn test_mac_to_uuid() {
        let mac = "04:7c:16:eb:74:ed";
        let uuid1 = mac_to_uuid(mac);

        // UUID should be deterministic - same MAC = same UUID
        let uuid2 = mac_to_uuid(mac);
        assert_eq!(uuid1, uuid2);

        // Different MACs should produce different UUIDs
        let mac2 = "04:7c:16:eb:74:ee";
        let uuid3 = mac_to_uuid(mac2);
        assert_ne!(uuid1, uuid3);

        println!("MAC {} -> UUID {}", mac, uuid1);
        println!("MAC {} -> UUID {}", mac2, uuid3);
    }
}
