use core::iter;
use core::str;
use stringprep::tables;
use unicode_normalization;
use unicode_normalization::UnicodeNormalization as _;
use unicode_properties::UnicodeGeneralCategory as _;

pub(super) struct Profile<'a> {
    inner: Canonical<Normalized<'a>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Unit {
    Space,
    Character(char),
}

struct Units<I: Iterator<Item = char>> {
    inner: iter::Peekable<I>,
}

struct Ascii<'a> {
    inner: str::Bytes<'a>,
}

struct Folded<'a> {
    inner: str::Chars<'a>,
    current: Option<tables::CaseFoldForNfkc>,
}

enum Normalized<'a> {
    Ascii(Ascii<'a>),
    Unicode(unicode_normalization::Recompositions<Folded<'a>>),
}

struct Canonical<I: Iterator<Item = char>> {
    units: Units<I>,
    queue: [char; 3],
    position: usize,
    queued: usize,
    started: bool,
    finished: bool,
}

impl<'a> Profile<'a> {
    pub(super) fn new(value: &'a str) -> Self {
        Self {
            inner: Canonical::new(normalized(value)),
        }
    }

    pub(super) fn is_valid(value: &str) -> bool {
        (value.is_ascii()
            || !value
                .chars()
                .filter_map(mapped)
                .any(tables::unassigned_code_point))
            && !normalized(value).any(prohibited)
    }
}

impl Iterator for Profile<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<I: Iterator<Item = char>> Units<I> {
    fn new(inner: I) -> Self {
        Self {
            inner: inner.peekable(),
        }
    }
}

impl Iterator for Ascii<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let byte = self.inner.next()?;
            match byte {
                0x00..=0x08 | 0x0e..=0x1f | 0x7f => {}
                0x09..=0x0d => return Some(' '),
                _ => return Some(byte.to_ascii_lowercase() as char),
            }
        }
    }
}

impl Iterator for Folded<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(current) = &mut self.current
                && let Some(character) = current.next()
            {
                return Some(character);
            }
            let character = self.inner.by_ref().find_map(mapped)?;
            self.current = Some(tables::case_fold_for_nfkc(character));
        }
    }
}

impl Iterator for Normalized<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Ascii(iterator) => iterator.next(),
            Self::Unicode(iterator) => iterator.next(),
        }
    }
}

impl<I: Iterator<Item = char>> Iterator for Units<I> {
    type Item = Unit;

    fn next(&mut self) -> Option<Self::Item> {
        let character = self.inner.next()?;
        let followed_by_mark = self.inner.peek().is_some_and(|next| {
            next.general_category_group() == unicode_properties::GeneralCategoryGroup::Mark
        });
        Some(if character == ' ' && !followed_by_mark {
            Unit::Space
        } else {
            Unit::Character(character)
        })
    }
}

impl<I: Iterator<Item = char>> Canonical<I> {
    fn new(inner: I) -> Self {
        Self {
            units: Units::new(inner),
            queue: ['\0'; 3],
            position: 0,
            queued: 0,
            started: false,
            finished: false,
        }
    }

    fn fill(&mut self, values: &[char]) {
        self.queue[..values.len()].copy_from_slice(values);
        self.position = 0;
        self.queued = values.len();
    }

    fn fill_start(&mut self) {
        loop {
            match self.units.next() {
                Some(Unit::Space) => {}
                Some(Unit::Character(character)) => {
                    self.fill(&[' ', character]);
                    self.started = true;
                    return;
                }
                None => {
                    self.fill(&[' ', ' ']);
                    self.finished = true;
                    return;
                }
            }
        }
    }

    fn fill_body(&mut self) {
        match self.units.next() {
            Some(Unit::Character(character)) => self.fill(&[character]),
            Some(Unit::Space) => loop {
                match self.units.next() {
                    Some(Unit::Space) => {}
                    Some(Unit::Character(character)) => {
                        self.fill(&[' ', ' ', character]);
                        return;
                    }
                    None => {
                        self.fill(&[' ']);
                        self.finished = true;
                        return;
                    }
                }
            },
            None => {
                self.fill(&[' ']);
                self.finished = true;
            }
        }
    }
}

impl<I: Iterator<Item = char>> Iterator for Canonical<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.queued {
            if self.finished {
                return None;
            }
            if self.started {
                self.fill_body();
            } else {
                self.fill_start();
            }
        }
        let character = self.queue[self.position];
        self.position += 1;
        Some(character)
    }
}

fn normalized(value: &str) -> Normalized<'_> {
    if value.is_ascii() {
        Normalized::Ascii(Ascii {
            inner: value.bytes(),
        })
    } else {
        Normalized::Unicode(
            Folded {
                inner: value.chars(),
                current: None,
            }
            .nfkc(),
        )
    }
}

fn mapped(character: char) -> Option<char> {
    if mapped_to_nothing(character) {
        None
    } else if mapped_to_space(character) {
        Some(' ')
    } else {
        Some(character)
    }
}

fn mapped_to_nothing(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{0008}'
            | '\u{000e}'..='\u{001f}'
            | '\u{007f}'..='\u{0084}'
            | '\u{0086}'..='\u{009f}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{1806}'
            | '\u{180b}'..='\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206a}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffc}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

fn mapped_to_space(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn prohibited(character: char) -> bool {
    tables::unassigned_code_point(character)
        || tables::change_display_properties_or_deprecated(character)
        || tables::private_use(character)
        || tables::non_character_code_point(character)
        || tables::surrogate_code(character)
        || character == '\u{fffd}'
}
