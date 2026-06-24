//! verify.rs — числовой код безопасности (safety number) для сверки контакта.
//!
//! Личность узла = его публичный ключ (NodeId). Отображаемые имена НЕ удостоверены:
//! кто угодно может назваться «Alice». Код безопасности позволяет ВНЕ сети (звонок,
//! личная встреча, другой мессенджер) убедиться, что NodeId собеседника — тот самый.
//! Код симметричен (оба узла видят одинаковые цифры) и меняется, если у собеседника
//! другой ключ — то есть подмена личности сразу заметна.

/// Код безопасности для пары идентификаторов (hex-строки NodeId).
/// 40 цифр группами по 5 — удобно зачитать вслух и сверить.
pub fn safety_number(id_a: &str, id_b: &str) -> String {
    // Сортируем, чтобы обе стороны получили один и тот же код независимо от порядка.
    let (lo, hi) = if id_a <= id_b { (id_a, id_b) } else { (id_b, id_a) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"void-connect/safety-number/v1");
    hasher.update(lo.as_bytes());
    hasher.update(b"\n");
    hasher.update(hi.as_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes(); // 32 байта
    let mut groups = Vec::with_capacity(8);
    for i in 0..8 {
        let v = u32::from_le_bytes([
            bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3],
        ]) % 100_000;
        groups.push(format!("{:05}", v));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_independent_of_order() {
        assert_eq!(safety_number("aa11", "bb22"), safety_number("bb22", "aa11"));
    }

    #[test]
    fn differs_per_pair() {
        assert_ne!(safety_number("aa", "bb"), safety_number("aa", "cc"));
        // Смена ключа собеседника меняет код — подмена заметна.
        assert_ne!(safety_number("me", "friend"), safety_number("me", "impostor"));
    }

    #[test]
    fn format_is_8_groups_of_5_digits() {
        let s = safety_number("x", "y");
        let groups: Vec<&str> = s.split(' ').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }
}
