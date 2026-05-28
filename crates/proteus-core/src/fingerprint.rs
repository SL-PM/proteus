//! Wire-fingerprint measurement (v0.5 M11.5).
//!
//! Quantifies how distinguishable one set of traffic observations is
//! from another (e.g. PROTEUS wire-frame sizes vs. a reference "cover"
//! distribution). This module is **pure and deterministic** — it only
//! does the math. Generating the observations (running a real flow and
//! recording frame sizes / inter-arrival gaps) lives in the harness
//! (M12.5), not here.
//!
//! ## Why total-variation distance instead of a trained classifier
//!
//! For two classes with equal prior probability, the **total-variation
//! distance** `TV(P, Q) = ½ Σ |P(k) − Q(k)|` is exactly the advantage
//! the best possible classifier has over guessing:
//!
//! ```text
//! best_accuracy = (1 + TV) / 2
//! ```
//!
//! * `TV = 0` → the distributions are identical → no classifier beats a
//!   coin flip (`accuracy = 0.5`). Indistinguishable.
//! * `TV = 1` → disjoint supports → a classifier is always right
//!   (`accuracy = 1.0`). Trivially distinguishable.
//!
//! So TV gives us the metric we want — "how well can an adversary tell
//! PROTEUS from cover traffic" — with no training, no test/train split,
//! no overfitting, and full determinism. We compare
//! `TV(unshaped_proteus, cover)` against `TV(shaped_proteus, cover)`:
//! if the shaping helps, the latter is smaller (PROTEUS moved toward
//! the cover distribution).
//!
//! Keys are `u64` so the same code serves size buckets (bytes) and gap
//! buckets (milliseconds); the caller chooses the bucketing.

use std::collections::BTreeMap;

/// A discrete probability distribution over `u64`-keyed bins.
/// Probabilities sum to 1 (unless built from zero samples, when it is
/// empty and treated as having no mass).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Distribution {
    /// bin key → probability mass.
    bins: BTreeMap<u64, f64>,
    /// number of observations the distribution was built from.
    n: usize,
}

impl Distribution {
    /// Build a normalized distribution by counting `samples` into bins
    /// keyed by their exact value. (Caller pre-buckets if coarser bins
    /// are wanted — e.g. `size / 64`.)
    pub fn from_samples<I: IntoIterator<Item = u64>>(samples: I) -> Self {
        let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
        let mut n = 0usize;
        for s in samples {
            *counts.entry(s).or_insert(0) += 1;
            n += 1;
        }
        let mut bins = BTreeMap::new();
        if n > 0 {
            let total = n as f64;
            for (k, c) in counts {
                bins.insert(k, c as f64 / total);
            }
        }
        Self { bins, n }
    }

    /// Number of observations the distribution was built from.
    pub fn count(&self) -> usize {
        self.n
    }

    /// Number of distinct occupied bins. Padding collapses this toward
    /// the bucket count, which is itself a (coarse) fingerprint signal.
    pub fn distinct_bins(&self) -> usize {
        self.bins.len()
    }

    /// Probability mass in bin `k` (0.0 if absent).
    pub fn mass(&self, k: u64) -> f64 {
        self.bins.get(&k).copied().unwrap_or(0.0)
    }

    /// Total-variation distance to `other`, in `[0, 1]`.
    /// `0.5 · Σ_k |P(k) − Q(k)|` over the union of keys.
    pub fn total_variation(&self, other: &Self) -> f64 {
        let mut keys: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        keys.extend(self.bins.keys());
        keys.extend(other.bins.keys());
        let sum: f64 = keys
            .into_iter()
            .map(|k| (self.mass(k) - other.mass(k)).abs())
            .sum();
        let tv = 0.5 * sum;
        // Clamp to [0,1] to absorb floating-point drift.
        tv.clamp(0.0, 1.0)
    }
}

/// Best accuracy any binary classifier can achieve separating two
/// equal-prior classes whose distributions differ by `tv`
/// (total-variation distance). `(1 + tv) / 2`, clamped to `[0.5, 1.0]`.
pub fn optimal_classifier_accuracy(tv: f64) -> f64 {
    ((1.0 + tv) / 2.0).clamp(0.5, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn from_samples_normalizes() {
        let d = Distribution::from_samples([1u64, 1, 2, 4]);
        assert_eq!(d.count(), 4);
        assert_eq!(d.distinct_bins(), 3);
        assert!(approx(d.mass(1), 0.5));
        assert!(approx(d.mass(2), 0.25));
        assert!(approx(d.mass(4), 0.25));
        assert!(approx(d.mass(3), 0.0));
        // Masses sum to 1.
        let total: f64 = [1u64, 2, 4].iter().map(|&k| d.mass(k)).sum();
        assert!(approx(total, 1.0));
    }

    #[test]
    fn empty_distribution_has_no_mass() {
        let d = Distribution::from_samples(std::iter::empty::<u64>());
        assert_eq!(d.count(), 0);
        assert_eq!(d.distinct_bins(), 0);
        assert!(approx(d.mass(0), 0.0));
    }

    #[test]
    fn identical_distributions_have_tv_zero() {
        let a = Distribution::from_samples([1u64, 2, 2, 3]);
        let b = Distribution::from_samples([3u64, 2, 1, 2]); // same multiset
        assert!(approx(a.total_variation(&b), 0.0));
        assert!(approx(optimal_classifier_accuracy(0.0), 0.5));
    }

    #[test]
    fn disjoint_distributions_have_tv_one() {
        let a = Distribution::from_samples([1u64, 1, 1]);
        let b = Distribution::from_samples([9u64, 9, 9]);
        assert!(approx(a.total_variation(&b), 1.0));
        assert!(approx(optimal_classifier_accuracy(1.0), 1.0));
    }

    #[test]
    fn half_overlap_has_tv_one_half() {
        // a: all mass on 1. b: half on 1, half on 2.
        let a = Distribution::from_samples([1u64, 1, 1, 1]);
        let b = Distribution::from_samples([1u64, 1, 2, 2]);
        // |1.0-0.5| + |0.0-0.5| = 1.0; ×0.5 = 0.5.
        assert!(approx(a.total_variation(&b), 0.5));
        assert!(approx(optimal_classifier_accuracy(0.5), 0.75));
    }

    #[test]
    fn tv_is_symmetric() {
        let a = Distribution::from_samples([1u64, 2, 3, 3, 3]);
        let b = Distribution::from_samples([1u64, 1, 2, 4, 5]);
        assert!(approx(a.total_variation(&b), b.total_variation(&a)));
    }

    #[test]
    fn shaping_toward_cover_reduces_tv() {
        // Cover: a smooth-ish spread over 5 values.
        let cover = Distribution::from_samples([10u64, 20, 30, 40, 50, 20, 30, 30, 40, 20]);
        // Unshaped PROTEUS: one sharp spike (very distinguishable).
        let unshaped = Distribution::from_samples([35u64; 10]);
        // "Shaped": spread out to resemble the cover more.
        let shaped = Distribution::from_samples([10u64, 20, 30, 40, 50, 20, 30, 40, 30, 20]);
        let tv_unshaped = unshaped.total_variation(&cover);
        let tv_shaped = shaped.total_variation(&cover);
        assert!(
            tv_shaped < tv_unshaped,
            "shaping should move toward cover: shaped={tv_shaped}, unshaped={tv_unshaped}"
        );
    }

    #[test]
    fn optimal_accuracy_clamps() {
        assert!(approx(optimal_classifier_accuracy(-0.3), 0.5)); // garbage in → floor
        assert!(approx(optimal_classifier_accuracy(2.0), 1.0)); // garbage in → ceil
    }
}
