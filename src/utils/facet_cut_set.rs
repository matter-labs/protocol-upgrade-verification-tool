use alloy::primitives::Address;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::cmp::Ordering;
use std::ops::Add;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Add,
    Replace,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetInfo {
    pub(crate) facet: Address,
    pub(crate) action: Action,
    pub(crate) is_freezable: bool,
    pub(crate) selectors: HashSet<[u8; 4]>,
}

impl Hash for FacetInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the fields that are already in a deterministic order.
        self.facet.hash(state);
        self.action.hash(state);
        self.is_freezable.hash(state);

        // For the selectors (a HashSet), sort them first so that the order is deterministic.
        // Note: [u8; 4] implements Ord, so sorting is available.
        let mut selectors: Vec<&[u8; 4]> = self.selectors.iter().collect();
        selectors.sort();
        for selector in selectors {
            selector.hash(state);
        }
    }
}

#[derive(Debug, Clone, Eq)]
pub struct FacetCutSet {
    facets: HashSet<FacetInfo>,
}

impl PartialEq for FacetCutSet {
    fn eq(&self, other: &Self) -> bool {
        self.facets == other.facets
    }
}

impl FacetCutSet {
    pub fn new() -> Self {
        Self {
            facets: HashSet::new(),
        }
    }

    pub fn add_facet(&mut self, facet: FacetInfo) {
        self.facets.insert(
            facet
        );
    }

    pub fn merge(mut self, another_set: FacetCutSet) -> Self {
        for new_facet in another_set.facets {
            self.facets.insert(new_facet);
        }

        self
    }
}

impl PartialOrd for FacetCutSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.facets.len().cmp(&other.facets.len()))
    }
}

impl Ord for FacetCutSet {
    fn cmp(&self, other: &Self) -> Ordering {
        self.facets.len().cmp(&other.facets.len())
    }
}
