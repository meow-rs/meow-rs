//! Domain trie with two representations:
//!
//! * **Building** — a flat node vector plus one hash map of `(parent,
//!   label-id) → child` edges and one label interner. Insert is O(labels)
//!   with no per-node heap objects; the same structure answers searches so
//!   callers that never seal (hosts tables, fake-IP filters) still work.
//! * **Sealed** — a breadth-first node array where each node is 8 bytes
//!   (label offset + first-child index with a 3-bit value mask), the
//!   children of a node are one contiguous, label-sorted run, all label
//!   bytes live in a single deduplicated `.`-terminated arena, and values
//!   live in one side table indexed by a sampled rank over the value masks.
//!   A sealed trie holds exactly four heap allocations regardless of size.
//!
//! Semantics (unchanged): `exact` beats `*.` (one extra label) beats `.`
//! (any depth) at the deepest matching node; `+.x` is `*.x` and `.x`
//! together; first insert wins per (node, kind).

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

pub struct DomainTrie<T: Clone + 'static> {
    state: TrieState<T>,
    len: usize,
}

enum TrieState<T> {
    Building(Builder<T>),
    Sealed(Sealed<T>),
}

const MASK_EXACT: u8 = 1;
const MASK_STAR: u8 = 2;
const MASK_DOT: u8 = 4;

#[derive(Clone, Copy)]
enum MatchKind {
    Exact,
    Star,
    Dot,
}

// ---------------------------------------------------------------------------
// Hashing: fixed-width integer keys (edges) and short byte strings (labels)
// go through one multiplicative hasher — SipHash would dominate build time
// for a million-domain geosite load.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FastHasher(u64);

const HASH_MUL: u64 = 0x9E37_79B9_7F4A_7C15;

impl FastHasher {
    #[inline]
    fn mix(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(29) ^ word).wrapping_mul(HASH_MUL);
    }
}

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        // Fold the high bits down: hashbrown takes its tag from the top
        // seven bits and its bucket from the low bits.
        self.0 ^ (self.0 >> 32)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, rest) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.mix(u64::from_le_bytes(*chunk));
        }
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            self.mix(u64::from_le_bytes(buf));
        }
        self.mix(bytes.len() as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.mix(u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.mix(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.mix(i as u64);
    }
}

type FastBuild = BuildHasherDefault<FastHasher>;

// ---------------------------------------------------------------------------
// Build phase
// ---------------------------------------------------------------------------

struct BuildNode<T> {
    label: u32,
    exact: Option<T>,
    star: Option<T>,
    dot: Option<T>,
}

struct Builder<T> {
    /// Index 0 is the root (created lazily on first insert).
    nodes: Vec<BuildNode<T>>,
    /// `(parent node, label id) → child node`.
    edges: HashMap<(u32, u32), u32, FastBuild>,
    /// Interned labels; id 0 is the empty root label.
    labels: HashMap<Box<str>, u32, FastBuild>,
}

impl<T> Builder<T> {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: HashMap::default(),
            labels: HashMap::default(),
        }
    }

    fn ensure_root(&mut self) {
        if self.nodes.is_empty() {
            self.labels.insert(Box::from(""), 0);
            self.nodes.push(BuildNode {
                label: 0,
                exact: None,
                star: None,
                dot: None,
            });
        }
    }

    fn child_or_insert(&mut self, parent: u32, label: &str) -> u32 {
        let id = match self.labels.get(label) {
            Some(&id) => id,
            None => {
                let id = u32::try_from(self.labels.len()).expect("label id overflow");
                self.labels.insert(Box::from(label), id);
                id
            }
        };
        match self.edges.entry((parent, id)) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let next = u32::try_from(self.nodes.len()).expect("node index overflow");
                e.insert(next);
                self.nodes.push(BuildNode {
                    label: id,
                    exact: None,
                    star: None,
                    dot: None,
                });
                next
            }
        }
    }

    #[inline]
    fn child(&self, parent: u32, label: &str) -> Option<u32> {
        let id = *self.labels.get(label)?;
        self.edges.get(&(parent, id)).copied()
    }

    /// Child lookup with an ASCII-case-insensitive label: stored labels are
    /// lower-case, so lower the query label into a stack buffer first.
    fn child_ci(&self, parent: u32, label: &str) -> Option<u32> {
        if !label.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.child(parent, label);
        }
        let mut buf = [0u8; 256];
        if label.len() <= buf.len() {
            let lower = &mut buf[..label.len()];
            lower.copy_from_slice(label.as_bytes());
            lower.make_ascii_lowercase();
            // ASCII case folding preserves UTF-8 validity.
            let lower = std::str::from_utf8(lower).ok()?;
            self.child(parent, lower)
        } else {
            self.child(parent, &label.to_ascii_lowercase())
        }
    }

    fn into_sealed(mut self) -> Sealed<T> {
        self.ensure_root();
        let n = self.nodes.len();
        assert!(
            n < (1 << MASK_SHIFT),
            "DomainTrie: sealed form supports at most 2^29 nodes"
        );

        // CSR grouping of children by parent (edges are unordered). The
        // fill pass advances each parent's cursor in place, so afterwards
        // `bounds[p]` is the *end* of parent p's run and `bounds[p - 1]`
        // (or 0) its start — one array instead of start + cursor copies,
        // which matters because the edge map is still alive here.
        let mut bounds = vec![0u32; n + 1];
        for &(parent, _) in self.edges.keys() {
            bounds[parent as usize + 1] += 1;
        }
        for i in 0..n {
            bounds[i + 1] += bounds[i];
        }
        let mut children_old = vec![0u32; n.saturating_sub(1)];
        for (&(parent, _), &child) in &self.edges {
            let slot = &mut bounds[parent as usize];
            children_old[*slot as usize] = child;
            *slot += 1;
        }
        self.edges = HashMap::default();
        let run = |p: usize| -> std::ops::Range<usize> {
            let start = if p == 0 { 0 } else { bounds[p - 1] as usize };
            start..bounds[p] as usize
        };

        // Label id → bytes, for sorting children and building the arena.
        let mut label_by_id: Vec<&str> = vec![""; self.labels.len()];
        for (label, &id) in &self.labels {
            label_by_id[id as usize] = label;
        }
        let nodes = &self.nodes;
        for p in 0..n {
            let group = &mut children_old[run(p)];
            group.sort_unstable_by(|&a, &b| {
                let la = label_by_id[nodes[a as usize].label as usize].as_bytes();
                let lb = label_by_id[nodes[b as usize].label as usize].as_bytes();
                la.cmp(lb)
            });
        }

        // Breadth-first renumbering: every node's children become one
        // contiguous run, and runs appear in node order, so `first_child`
        // of node i+1 doubles as the end of node i's run.
        let mut order: Vec<u32> = Vec::with_capacity(n);
        let mut first_child: Vec<u32> = Vec::with_capacity(n + 1);
        order.push(0);
        let mut i = 0;
        while i < order.len() {
            let old = order[i] as usize;
            first_child.push(order.len() as u32);
            order.extend_from_slice(&children_old[run(old)]);
            i += 1;
        }
        debug_assert_eq!(order.len(), n);
        drop(children_old);
        drop(bounds);

        // Arena: every label followed by a `.` terminator (labels come from
        // splitting on `.`, so the byte never occurs inside one). Nodes then
        // need only an offset, and comparisons read straight from the arena.
        let total_label_bytes: usize = label_by_id.iter().map(|l| l.len() + 1).sum();
        assert!(
            u32::try_from(total_label_bytes).is_ok(),
            "DomainTrie: label arena exceeds u32 range"
        );
        let mut label_offset: Vec<u32> = Vec::with_capacity(label_by_id.len());
        let mut labels: Vec<u8> = Vec::with_capacity(total_label_bytes);
        for label in &label_by_id {
            label_offset.push(labels.len() as u32);
            labels.extend_from_slice(label.as_bytes());
            labels.push(b'.');
        }
        drop(label_by_id);

        let mut sealed_nodes: Vec<Node> = Vec::with_capacity(n + 1);
        let mut values: Vec<T> = Vec::new();
        let mut value_base: Vec<u32> = Vec::with_capacity(n / VALUE_BLOCK + 1);
        for (new_idx, &old) in order.iter().enumerate() {
            if new_idx % VALUE_BLOCK == 0 {
                value_base.push(u32::try_from(values.len()).expect("value index overflow"));
            }
            let node = &mut self.nodes[old as usize];
            let mut mask = 0u8;
            if let Some(v) = node.exact.take() {
                values.push(v);
                mask |= MASK_EXACT;
            }
            if let Some(v) = node.star.take() {
                values.push(v);
                mask |= MASK_STAR;
            }
            if let Some(v) = node.dot.take() {
                values.push(v);
                mask |= MASK_DOT;
            }
            sealed_nodes.push(Node {
                label: label_offset[node.label as usize],
                child_mask: first_child[new_idx] | (u32::from(mask) << MASK_SHIFT),
            });
        }
        // Sentinel: end of the last node's child run.
        sealed_nodes.push(Node {
            label: 0,
            child_mask: n as u32,
        });

        Sealed {
            nodes: sealed_nodes.into_boxed_slice(),
            values: values.into_boxed_slice(),
            value_base: value_base.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sealed phase
// ---------------------------------------------------------------------------

const MASK_SHIFT: u32 = 29;
const CHILD_MASK: u32 = (1 << MASK_SHIFT) - 1;
/// Nodes per `value_base` sample. Value lookups (only on the hit path, for
/// non-ZST values) popcount at most this many masks.
const VALUE_BLOCK: usize = 32;

/// One sealed node. `label` is the byte offset of this node's label in the
/// arena; `child_mask` packs the index of the first child (low 29 bits) with
/// the value-presence mask (high 3 bits).
#[derive(Clone, Copy)]
struct Node {
    label: u32,
    child_mask: u32,
}

impl Node {
    #[inline]
    fn first_child(self) -> usize {
        (self.child_mask & CHILD_MASK) as usize
    }

    #[inline]
    fn mask(self) -> u8 {
        (self.child_mask >> MASK_SHIFT) as u8
    }
}

struct Sealed<T> {
    /// `n + 1` entries; the trailing sentinel closes the last child run.
    nodes: Box<[Node]>,
    /// Present values in node order, exact/star/dot within a node.
    values: Box<[T]>,
    /// `values` index of the first value in each `VALUE_BLOCK`-node block.
    value_base: Box<[u32]>,
    /// Deduplicated labels, each terminated by `.`.
    labels: Box<[u8]>,
}

impl<T> Sealed<T> {
    /// Byte-wise compare of the `.`-terminated label at `offset` against a
    /// query label (which never contains `.`). Orders exactly like
    /// `stored.cmp(query)` on the untermimated bytes, which is the order the
    /// child runs were sorted in.
    #[inline]
    fn cmp_label<const CI: bool>(&self, offset: u32, query: &[u8]) -> Ordering {
        let stored = &self.labels[offset as usize..];
        for (i, &q) in query.iter().enumerate() {
            let s = stored[i];
            if s == b'.' {
                return Ordering::Less;
            }
            let q = if CI { q.to_ascii_lowercase() } else { q };
            match s.cmp(&q) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        if stored[query.len()] == b'.' {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }

    #[inline]
    fn children(&self, node: usize) -> (usize, &[Node]) {
        let start = self.nodes[node].first_child();
        let end = self.nodes[node + 1].first_child();
        (start, &self.nodes[start..end])
    }

    #[inline]
    fn find_child<const CI: bool>(&self, node: usize, label: &[u8]) -> Option<usize> {
        let (start, children) = self.children(node);
        children
            .binary_search_by(|c| self.cmp_label::<CI>(c.label, label))
            .ok()
            .map(|i| start + i)
    }

    /// Index into `values` of this node's first value: sampled base plus
    /// the popcount of every earlier mask in the block. Free for ZST values.
    #[inline]
    fn value_index(&self, node: usize) -> usize {
        if std::mem::size_of::<T>() == 0 {
            return 0;
        }
        let block = node / VALUE_BLOCK;
        let mut idx = self.value_base[block] as usize;
        for n in &self.nodes[block * VALUE_BLOCK..node] {
            idx += (n.child_mask >> MASK_SHIFT).count_ones() as usize;
        }
        idx
    }

    #[inline]
    fn exact(&self, node: usize) -> Option<&T> {
        let mask = self.nodes[node].mask();
        (mask & MASK_EXACT != 0).then(|| &self.values[self.value_index(node)])
    }

    #[inline]
    fn star(&self, node: usize) -> Option<&T> {
        let mask = self.nodes[node].mask();
        (mask & MASK_STAR != 0)
            .then(|| &self.values[self.value_index(node) + usize::from(mask & MASK_EXACT)])
    }

    #[inline]
    fn dot(&self, node: usize) -> Option<&T> {
        let mask = self.nodes[node].mask();
        (mask & MASK_DOT != 0).then(|| {
            &self.values
                [self.value_index(node) + (mask & (MASK_EXACT | MASK_STAR)).count_ones() as usize]
        })
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl<T: Clone + 'static> DomainTrie<T> {
    pub fn new() -> Self {
        DomainTrie {
            state: TrieState::Building(Builder::new()),
            len: 0,
        }
    }

    pub fn insert(&mut self, domain: &str, data: T) -> bool {
        let trimmed = domain.trim();
        let lowered: Cow<'_, str> = if trimmed
            .bytes()
            .any(|b| b.is_ascii_uppercase() || !b.is_ascii())
        {
            Cow::Owned(trimmed.to_lowercase())
        } else {
            Cow::Borrowed(trimmed)
        };
        let domain = &*lowered;
        if domain.is_empty() {
            return false;
        }

        if let Some(rest) = domain.strip_prefix("+.") {
            if rest.is_empty() {
                return false;
            }
            self.insert_into_tree(rest, data.clone(), MatchKind::Star);
            self.insert_into_tree(rest, data, MatchKind::Dot);
            self.len += 2;
            return true;
        }

        if let Some(rest) = domain.strip_prefix("*.") {
            if rest.is_empty() {
                return false;
            }
            self.insert_into_tree(rest, data, MatchKind::Star);
            self.len += 1;
            return true;
        }

        if let Some(rest) = domain.strip_prefix('.') {
            if rest.is_empty() {
                return false;
            }
            self.insert_into_tree(rest, data, MatchKind::Dot);
            self.len += 1;
            return true;
        }

        self.insert_into_tree(domain, data, MatchKind::Exact);
        self.len += 1;
        true
    }

    fn insert_into_tree(&mut self, base_domain: &str, value: T, kind: MatchKind) {
        let TrieState::Building(builder) = &mut self.state else {
            return;
        };
        builder.ensure_root();
        let mut node = 0u32;
        for label in base_domain.rsplit('.') {
            node = builder.child_or_insert(node, label);
        }
        let slot = &mut builder.nodes[node as usize];
        match kind {
            MatchKind::Exact => {
                slot.exact.get_or_insert(value);
            }
            MatchKind::Star => {
                slot.star.get_or_insert(value);
            }
            MatchKind::Dot => {
                slot.dot.get_or_insert(value);
            }
        }
    }

    /// Freeze the trie into its compact breadth-first layout. Idempotent.
    /// A sealed trie ignores further inserts.
    pub fn seal(&mut self) {
        if let TrieState::Building(_) = &self.state {
            let old = std::mem::replace(&mut self.state, TrieState::Building(Builder::new()));
            if let TrieState::Building(builder) = old {
                self.state = TrieState::Sealed(builder.into_sealed());
            }
        }
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        let trimmed = domain.trim();
        let query = trimmed.trim_end_matches('.');
        if query.is_empty() {
            return None;
        }
        if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            self.search_best::<true>(query)
        } else {
            self.search_best::<false>(query)
        }
    }

    /// Search with a pre-lowercased domain. Skips the case-folding check.
    pub fn search_normalized(&self, domain_lower: &str) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        let query = domain_lower.trim_end_matches('.');
        if query.is_empty() {
            return None;
        }
        self.search_best::<false>(query)
    }

    /// Search with a pre-lowercased domain, returning the **minimum** value
    /// among all patterns matching the query — not the most-specific one.
    ///
    /// [`Self::search_normalized`] answers "which pattern is the best match"
    /// (exact beats wildcard, deeper beats shallower). First-match-wins rule
    /// engines need a different question answered: "what is the smallest rule
    /// index whose pattern matches this host". This walks the same path but
    /// folds the minimum over every matching exact/star/dot value.
    pub fn search_min_normalized(&self, domain_lower: &str) -> Option<&T>
    where
        T: Ord,
    {
        if self.len == 0 {
            return None;
        }
        let query = domain_lower.trim_end_matches('.');
        if query.is_empty() {
            return None;
        }
        let n = label_count(query);
        let mut best: Option<&T> = None;
        match &self.state {
            TrieState::Building(b) => {
                let mut node = 0u32;
                for (d, label) in query.rsplit('.').enumerate() {
                    let Some(child) = b.child(node, label) else {
                        break;
                    };
                    node = child;
                    let slot = &b.nodes[node as usize];
                    let remaining = n - d - 1;
                    if remaining == 0 {
                        fold_min(&mut best, slot.exact.as_ref());
                    } else {
                        if remaining == 1 {
                            fold_min(&mut best, slot.star.as_ref());
                        }
                        fold_min(&mut best, slot.dot.as_ref());
                    }
                }
            }
            TrieState::Sealed(s) => {
                let mut node = 0usize;
                for (d, label) in query.rsplit('.').enumerate() {
                    let Some(child) = s.find_child::<false>(node, label.as_bytes()) else {
                        break;
                    };
                    node = child;
                    let remaining = n - d - 1;
                    if remaining == 0 {
                        fold_min(&mut best, s.exact(node));
                    } else {
                        if remaining == 1 {
                            fold_min(&mut best, s.star(node));
                        }
                        fold_min(&mut best, s.dot(node));
                    }
                }
            }
        }
        best
    }

    /// Most-specific match: walk the query's labels from the TLD down; an
    /// exact hit at the leaf returns immediately, otherwise the deepest
    /// wildcard seen wins (`*.` over `.` at the same depth).
    fn search_best<const CI: bool>(&self, query: &str) -> Option<&T> {
        let n = label_count(query);
        let mut best: Option<&T> = None;
        match &self.state {
            TrieState::Building(b) => {
                let mut node = 0u32;
                for (d, label) in query.rsplit('.').enumerate() {
                    let child = if CI {
                        b.child_ci(node, label)
                    } else {
                        b.child(node, label)
                    };
                    let Some(child) = child else {
                        break;
                    };
                    node = child;
                    let slot = &b.nodes[node as usize];
                    let remaining = n - d - 1;
                    if remaining == 0 {
                        if let Some(v) = slot.exact.as_ref() {
                            return Some(v);
                        }
                    } else if remaining == 1 {
                        if let Some(v) = slot.star.as_ref() {
                            best = Some(v);
                        } else if let Some(v) = slot.dot.as_ref() {
                            best = Some(v);
                        }
                    } else if let Some(v) = slot.dot.as_ref() {
                        best = Some(v);
                    }
                }
            }
            TrieState::Sealed(s) => {
                let mut node = 0usize;
                for (d, label) in query.rsplit('.').enumerate() {
                    let Some(child) = s.find_child::<CI>(node, label.as_bytes()) else {
                        break;
                    };
                    node = child;
                    let remaining = n - d - 1;
                    if remaining == 0 {
                        if let Some(v) = s.exact(node) {
                            return Some(v);
                        }
                    } else if remaining == 1 {
                        if let Some(v) = s.star(node) {
                            best = Some(v);
                        } else if let Some(v) = s.dot(node) {
                            best = Some(v);
                        }
                    } else if let Some(v) = s.dot(node) {
                        best = Some(v);
                    }
                }
            }
        }
        best
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[inline]
fn label_count(query: &str) -> usize {
    query.bytes().filter(|&b| b == b'.').count() + 1
}

fn fold_min<'a, T: Ord>(best: &mut Option<&'a T>, candidate: Option<&'a T>) {
    if let Some(candidate) = candidate {
        match best {
            Some(current) if *current <= candidate => {}
            _ => *best = Some(candidate),
        }
    }
}

impl<T: Clone + 'static> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    struct NaiveMatcher {
        patterns: Vec<String>,
    }

    impl NaiveMatcher {
        fn new(patterns: &[String]) -> Self {
            NaiveMatcher {
                patterns: patterns.iter().map(|p| p.to_lowercase()).collect(),
            }
        }

        fn matches(&self, query: &str) -> bool {
            let q = query.to_lowercase();
            for pat in &self.patterns {
                if let Some(rest) = pat.strip_prefix("*.") {
                    if let Some(prefix) = q.strip_suffix(&format!(".{rest}")) {
                        if !prefix.is_empty() && !prefix.contains('.') {
                            return true;
                        }
                    }
                } else if let Some(rest) = pat.strip_prefix('.') {
                    if q.ends_with(&format!(".{rest}")) {
                        return true;
                    }
                } else if q == pat.as_str() {
                    return true;
                }
            }
            false
        }
    }

    fn build_trie(patterns: &[String]) -> DomainTrie<bool> {
        let mut trie = DomainTrie::new();
        for p in patterns {
            trie.insert(p, true);
        }
        trie
    }

    proptest! {
        #[test]
        fn matches_naive_reference(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let trie = build_trie(&patterns);
            let naive = NaiveMatcher::new(&patterns);
            for q in &queries {
                let trie_hit = trie.search(q).is_some();
                let naive_hit = naive.matches(q);
                prop_assert_eq!(
                    trie_hit,
                    naive_hit,
                    "divergence on query {:?} with patterns {:?}",
                    q,
                    patterns
                );
            }
        }

        #[test]
        fn matches_naive_reference_zst(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let mut trie: DomainTrie<()> = DomainTrie::new();
            for p in &patterns {
                trie.insert(p, ());
            }
            let naive = NaiveMatcher::new(&patterns);
            for q in &queries {
                let trie_hit = trie.search(q).is_some();
                let naive_hit = naive.matches(q);
                prop_assert_eq!(
                    trie_hit,
                    naive_hit,
                    "ZST divergence on query {:?} with patterns {:?}",
                    q,
                    patterns
                );
            }
        }

        #[test]
        fn sealed_matches_unsealed(
            patterns in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}|\\*\\.[a-z]{1,5}(\\.[a-z]{1,5}){0,2}",
                1..=20,
            ),
            queries in proptest::collection::vec(
                "[a-z]{1,5}(\\.[a-z]{1,5}){0,4}",
                1..=10,
            ),
        ) {
            let mut trie = build_trie(&patterns);
            let unsealed_results: Vec<_> = queries.iter().map(|q| trie.search(q).copied()).collect();
            trie.seal();
            for (q, expected) in queries.iter().zip(unsealed_results.iter()) {
                let sealed_result = trie.search(q).copied();
                prop_assert_eq!(
                    sealed_result,
                    *expected,
                    "sealed/unsealed divergence on query {:?}",
                    q,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_and_search() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("www.example.com"), None);
        assert_eq!(trie.search("foo.com"), None);
    }

    #[test]
    fn test_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&1));
        assert_eq!(trie.search("example.com"), None);
        assert_eq!(trie.search("a.b.example.com"), None);
    }

    #[test]
    fn test_dot_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert(".example.com", 1);
        assert_eq!(trie.search("example.com"), None);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&1));
    }

    #[test]
    fn test_plus_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("+.example.com", 1);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&1));
    }

    #[test]
    fn test_priority() {
        let mut trie = DomainTrie::new();
        trie.insert("www.example.com", 1);
        trie.insert("*.example.com", 2);
        trie.insert(".example.com", 3);
        assert_eq!(trie.search("www.example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&2));
        assert_eq!(trie.search("a.b.example.com"), Some(&3));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("Example.COM", 1);
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("EXAMPLE.COM"), Some(&1));
    }

    #[test]
    fn search_min_folds_across_all_matching_patterns() {
        let mut trie = DomainTrie::new();
        trie.insert("+.a.com", 1);
        trie.insert("+.b.a.com", 3);
        trie.insert("x.b.a.com", 7);

        // Most-specific search prefers the exact/deepest pattern...
        assert_eq!(trie.search_normalized("x.b.a.com"), Some(&7));
        // ...min search folds the minimum over every matching pattern.
        assert_eq!(trie.search_min_normalized("x.b.a.com"), Some(&1));
        assert_eq!(trie.search_min_normalized("y.b.a.com"), Some(&1));
        assert_eq!(trie.search_min_normalized("deep.y.b.a.com"), Some(&1));
        assert_eq!(trie.search_min_normalized("unrelated.com"), None);

        // Sealed trie must agree with the building trie.
        trie.seal();
        assert_eq!(trie.search_min_normalized("x.b.a.com"), Some(&1));
        assert_eq!(trie.search_min_normalized("deep.y.b.a.com"), Some(&1));
        assert_eq!(trie.search_min_normalized("unrelated.com"), None);
    }

    #[test]
    fn search_min_sees_star_dot_and_exact_values() {
        let mut trie = DomainTrie::new();
        trie.insert("exact.example.com", 9);
        trie.insert("*.example.com", 4);
        trie.insert(".example.com", 6);
        trie.seal();

        // exact(9) vs star(4, one label) vs dot(6): min of the matching set.
        assert_eq!(trie.search_min_normalized("exact.example.com"), Some(&4));
        // Two labels below: star no longer applies, dot(6) does.
        assert_eq!(trie.search_min_normalized("a.b.example.com"), Some(&6));
        // Apex: only an exact pattern could match, none present.
        assert_eq!(trie.search_min_normalized("example.com"), None);
    }

    #[test]
    fn test_many_exact_domains() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..200 {
            trie.insert(&format!("domain{i}.com"), ());
        }
        assert!(trie.search("domain0.com").is_some());
        assert!(trie.search("domain199.com").is_some());
        assert!(trie.search("domain200.com").is_none());
    }

    #[test]
    fn test_many_star_wildcards() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..110 {
            trie.insert(&format!("*.suffix{i}.com"), ());
        }
        assert!(trie.search("www.suffix0.com").is_some());
        assert!(trie.search("foo.suffix50.com").is_some());
        assert!(trie.search("suffix0.com").is_none());
        assert!(trie.search("a.b.suffix0.com").is_none());
    }

    #[test]
    fn test_apex_and_wildcard() {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for i in 0..60 {
            trie.insert(&format!("exact{i}.com"), ());
        }
        for i in 0..60 {
            trie.insert(&format!("+.wild{i}.com"), ());
        }
        assert!(trie.search("exact0.com").is_some());
        assert!(trie.search("sub.wild0.com").is_some());
        assert!(trie.search("a.b.wild0.com").is_some());
    }

    #[test]
    fn test_trie_map_value_retrieval() {
        let mut trie = DomainTrie::new();
        trie.insert("exact.com", 10);
        trie.insert("*.wild.com", 20);
        trie.insert(".deep.com", 30);
        assert_eq!(trie.search("exact.com"), Some(&10));
        assert_eq!(trie.search("foo.wild.com"), Some(&20));
        assert_eq!(trie.search("a.b.deep.com"), Some(&30));
        assert_eq!(trie.search("other.com"), None);
    }

    #[test]
    fn test_trie_map_first_insert_wins() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        trie.insert("*.example.com", 2);
        assert_eq!(trie.search("foo.example.com"), Some(&1));
    }

    #[test]
    fn test_trie_map_deep_dot_overrides_shallow() {
        let mut trie = DomainTrie::new();
        trie.insert(".com", 1);
        trie.insert(".google.com", 2);
        assert_eq!(trie.search("www.google.com"), Some(&2));
        assert_eq!(trie.search("foo.other.com"), Some(&1));
    }

    #[test]
    fn test_trie_map_star_beats_dot_same_level() {
        let mut trie = DomainTrie::new();
        trie.insert("*.example.com", 1);
        trie.insert(".example.com", 2);
        assert_eq!(trie.search("foo.example.com"), Some(&1));
        assert_eq!(trie.search("a.b.example.com"), Some(&2));
    }

    #[test]
    fn test_empty_trie() {
        let trie: DomainTrie<i32> = DomainTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.search("anything.com"), None);
    }

    #[test]
    fn test_sealed_search() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        trie.insert("*.example.com", 2);
        trie.insert(".example.com", 3);
        trie.seal();
        assert_eq!(trie.search("example.com"), Some(&1));
        assert_eq!(trie.search("foo.example.com"), Some(&2));
        assert_eq!(trie.search("a.b.example.com"), Some(&3));
        assert_eq!(trie.search("other.com"), None);
    }
}
