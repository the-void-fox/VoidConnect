//! «Марка работы» для личных сообщений незнакомцу (проект —
//! `Obsidian/Сеть доверия.md`, раздел «Личные сообщения»).
//!
//! Написать тому, у кого я не в сети доверия и не разрешён, можно только с
//! маркой: nonce, при котором
//! `SHA-256("void-connect/dm-pow/v1" ‖ отправитель ‖ получатель ‖ день ‖ nonce)`
//! начинается с [`POW_BITS`] нулевых битов (~1 млн хэшей, 1–2 с CPU). ID —
//! hex64 фиксированной длины, день и nonce — 8 байт big-endian. Марка привязана
//! к паре и дню по UTC: запросы тысяче людей стоят тысячи таких вычислений, а
//! одному собеседнику её хватает на весь день.

use sha2::{Digest, Sha256};
use void_core::identity::NodeId;

/// Сколько ведущих нулевых битов требуется.
pub const POW_BITS: u32 = 20;
const CONTEXT: &[u8] = b"void-connect/dm-pow/v1";
const DAY_SECS: i64 = 86_400;

/// Номер дня по UTC.
pub fn utc_day(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(DAY_SECS)
}

/// Хэш без nonce — общий префикс для перебора.
fn prefix(from: &NodeId, to: &NodeId, day: i64) -> Sha256 {
    Sha256::new()
        .chain_update(CONTEXT)
        .chain_update(from.as_str())
        .chain_update(to.as_str())
        .chain_update(day.to_be_bytes())
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for b in hash {
        if *b == 0 {
            bits += 8;
        } else {
            return bits + b.leading_zeros();
        }
    }
    bits
}

fn fits(prefix: &Sha256, nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&prefix.clone().chain_update(nonce.to_be_bytes()).finalize()) >= bits
}

/// Подбирает марку для пары на день `day`. Долгая операция (секунды) — звать
/// из `spawn_blocking`.
pub fn mint(from: &NodeId, to: &NodeId, day: i64) -> u64 {
    mint_bits(from, to, day, POW_BITS)
}

fn mint_bits(from: &NodeId, to: &NodeId, day: i64, bits: u32) -> u64 {
    let base = prefix(from, to, day);
    let start: u64 = rand::random();
    (0..)
        .map(|i| start.wrapping_add(i))
        .find(|n| fits(&base, *n, bits))
        .expect("перебор u64 не кончается")
}

/// Проверяет марку `from → to`; день по UTC — сегодняшний ±1 (часы узлов
/// расходятся, а сообщение могли отправить перед полуночью).
pub fn verify(from: &NodeId, to: &NodeId, now_secs: i64, nonce: u64) -> bool {
    verify_bits(from, to, now_secs, nonce, POW_BITS)
}

fn verify_bits(from: &NodeId, to: &NodeId, now_secs: i64, nonce: u64, bits: u32) -> bool {
    let today = utc_day(now_secs);
    (today - 1..=today + 1).any(|day| fits(&prefix(from, to, day), nonce, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId(format!("{:02x}", n).repeat(32))
    }

    /// Малая сложность — чтобы тесты шли быстро; логика та же.
    const BITS: u32 = 12;

    #[test]
    fn stamp_is_bound_to_pair_and_day() {
        let now = 1_800_000_000;
        let day = utc_day(now);
        let nonce = mint_bits(&id(1), &id(2), day, BITS);
        assert!(verify_bits(&id(1), &id(2), now, nonce, BITS));
        // Вчерашняя и завтрашняя (по часам получателя) марка ещё действует.
        assert!(verify_bits(&id(1), &id(2), now + DAY_SECS, nonce, BITS));
        assert!(verify_bits(&id(1), &id(2), now - DAY_SECS, nonce, BITS));
        // Позавчерашняя — нет (повторы почти невероятны: 2^-12 на попытку).
        let stale = (0..20)
            .map(|k| mint_bits(&id(1), &id(2), day - 2 - k, BITS))
            .filter(|n| verify_bits(&id(1), &id(2), now, *n, BITS))
            .count();
        assert!(stale <= 1, "устаревшие марки проходят: {stale} из 20");
        // Другой получатель или отправитель — марка не подходит.
        let reused = (3..23)
            .filter(|n| verify_bits(&id(1), &id(*n), now, nonce, BITS))
            .count();
        assert!(reused <= 1, "марка подошла чужой паре {reused} раз из 20");
    }

    #[test]
    fn zero_bits_counted_across_bytes() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x0f, 0xff]), 20);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn utc_day_handles_negative_time() {
        assert_eq!(utc_day(0), 0);
        assert_eq!(utc_day(DAY_SECS - 1), 0);
        assert_eq!(utc_day(-1), -1);
    }
}
