//! Password and passphrase generation.
//!
//! Character-class selection: separate switches for symbols, digits and
//! uppercase, an ambiguity-free mode, and at least one character from every
//! enabled class. The minimum is what makes a generated password match the
//! policy most sites state, and it is enforced after the random draw.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&*+-=?^_~";
const AMBIGUOUS: &str = "Il1O0o";

const WORDS: &[&str] = &[
    "amber", "anchor", "atlas", "beacon", "birch", "bison", "bramble", "canyon", "cedar", "cobalt",
    "comet", "coral", "crimson", "cypress", "delta", "dune", "ember", "falcon", "fern", "flint",
    "forge", "glacier", "granite", "harbor", "hazel", "heron", "hollow", "indigo", "ivory", "jade",
    "juniper", "kelp", "lagoon", "lantern", "lichen", "lumen", "maple", "meadow", "mesa", "moss",
    "nectar", "nimbus", "north", "oak", "obsidian", "onyx", "orchid", "osprey", "otter", "pebble",
    "pine", "quartz", "quill", "raven", "reef", "ridge", "river", "saffron", "sage", "slate",
    "sonnet", "spruce", "storm", "summit", "tundra", "umber", "valley", "velvet", "verde",
    "willow", "winter", "zephyr", "zircon",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateOptions {
    #[serde(default = "default_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub lowercase: bool,
    #[serde(default = "default_true")]
    pub uppercase: bool,
    #[serde(default = "default_true")]
    pub digits: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
    #[serde(default)]
    pub avoid_ambiguous: bool,
    #[serde(default)]
    pub passphrase: bool,
    #[serde(default = "default_words")]
    pub words: usize,
    #[serde(default = "default_separator")]
    pub separator: String,
}

fn default_length() -> usize {
    20
}
fn default_true() -> bool {
    true
}
fn default_words() -> usize {
    4
}
fn default_separator() -> String {
    "-".to_string()
}

impl Default for GenerateOptions {
    fn default() -> Self {
        GenerateOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            passphrase: false,
            words: 4,
            separator: "-".to_string(),
        }
    }
}

fn clean(set: &str, avoid_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

pub fn generate(options: &GenerateOptions) -> String {
    let mut rng = rand::thread_rng();
    if options.passphrase {
        let count = options.words.clamp(3, 12);
        let words: Vec<&str> = (0..count)
            .map(|_| *WORDS.choose(&mut rng).expect("word list is not empty"))
            .collect();
        return words.join(&options.separator);
    }

    let mut classes: Vec<Vec<char>> = Vec::new();
    if options.lowercase {
        classes.push(clean(LOWER, options.avoid_ambiguous));
    }
    if options.uppercase {
        classes.push(clean(UPPER, options.avoid_ambiguous));
    }
    if options.digits {
        classes.push(clean(DIGITS, options.avoid_ambiguous));
    }
    if options.symbols {
        classes.push(clean(SYMBOLS, options.avoid_ambiguous));
    }
    if classes.is_empty() {
        classes.push(clean(LOWER, options.avoid_ambiguous));
    }

    let length = options.length.clamp(8, 128);
    let mut pool: Vec<char> = classes.iter().flatten().copied().collect();
    pool.sort_unstable();
    pool.dedup();

    let mut out: Vec<char> = Vec::with_capacity(length);
    // Guarantee one character from every enabled class.
    for class in &classes {
        if out.len() < length {
            out.push(*class.choose(&mut rng).expect("class is not empty"));
        }
    }
    while out.len() < length {
        out.push(*pool.choose(&mut rng).expect("pool is not empty"));
    }
    out.shuffle(&mut rng);
    out.into_iter().collect()
}

pub fn entropy_bits(options: &GenerateOptions) -> f64 {
    let mut bits = 0.0;
    if options.passphrase {
        return (options.words.clamp(3, 12) as f64) * (WORDS.len() as f64).log2();
    }
    if options.lowercase {
        bits += (clean(LOWER, options.avoid_ambiguous).len() as f64).log2();
    }
    if options.uppercase {
        bits += (clean(UPPER, options.avoid_ambiguous).len() as f64).log2();
    }
    if options.digits {
        bits += (clean(DIGITS, options.avoid_ambiguous).len() as f64).log2();
    }
    if options.symbols {
        bits += (clean(SYMBOLS, options.avoid_ambiguous).len() as f64).log2();
    }
    let _ = rand::thread_rng().gen::<u8>();
    bits * options.length.clamp(8, 128) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        let opts = GenerateOptions {
            length: 32,
            ..Default::default()
        };
        let pw = generate(&opts);
        assert_eq!(pw.chars().count(), 32);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn avoid_ambiguous_filters_lookalikes() {
        let opts = GenerateOptions {
            length: 64,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let pw = generate(&opts);
        assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn passphrase_uses_requested_word_count() {
        let opts = GenerateOptions {
            passphrase: true,
            words: 5,
            separator: "-".into(),
            ..Default::default()
        };
        let phrase = generate(&opts);
        assert_eq!(phrase.split('-').count(), 5);
        assert!(phrase.split('-').all(|w| WORDS.contains(&w)));
    }

    #[test]
    fn two_draws_differ() {
        assert_ne!(
            generate(&GenerateOptions::default()),
            generate(&GenerateOptions::default())
        );
    }
}
