//! Face matching by cosine similarity between embeddings.

/// Cosine similarity in [-1, 1]; 0 when either vector has zero length.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm = |v: &[f32]| v.iter().map(|x| x * x).sum::<f32>().sqrt();
    let denom = norm(a) * norm(b);
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

pub fn best_match(known: &[(usize, Vec<f32>)], probe: &[f32]) -> Option<(usize, f32)> {
    known
        .iter()
        .map(|(model, emb)| (*model, cosine_similarity(emb, probe)))
        .max_by(|(_, a), (_, b)| a.total_cmp(b))
}

pub fn is_match(similarity: f32, min_similarity: f32) -> bool {
    similarity >= min_similarity
}

/// Margin below the least similar pair of a user's own samples.
pub const PERSONAL_MARGIN: f32 = 0.30;
/// Cap for a personal threshold, so one very consistent enrollment cannot
/// lock the user out.
pub const PERSONAL_CAP: f32 = 0.50;

/// Stricter threshold from the user's own enrollment: the least similar pair
/// of one model's samples minus [`PERSONAL_MARGIN`], capped at [`PERSONAL_CAP`].
/// Only ever used to raise the global threshold.
pub fn personal_threshold(known: &[(usize, Vec<f32>)]) -> Option<f32> {
    let mut lowest: Option<f32> = None;
    for (i, (model, a)) in known.iter().enumerate() {
        for (other, b) in &known[i + 1..] {
            if model == other {
                let similarity = cosine_similarity(a, b);
                lowest = Some(lowest.map_or(similarity, |l| l.min(similarity)));
            }
        }
    }
    lowest.map(|l| (l - PERSONAL_MARGIN).min(PERSONAL_CAP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_orthogonal_opposite() {
        assert!((cosine_similarity(&[1.0, 2.0], &[2.0, 4.0]) - 1.0).abs() < 1e-6);
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]), 0.0);
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 0.0]), 0.0);
    }

    #[test]
    fn picks_most_similar_model() {
        let known = vec![
            (0, vec![1.0, 0.0]),
            (3, vec![0.6, 0.8]),
            (3, vec![0.0, 1.0]),
        ];
        let (model, sim) = best_match(&known, &[0.5, 0.9]).unwrap();
        assert_eq!(model, 3);
        assert!(is_match(sim, 0.9));
        assert!(!is_match(sim, 0.999));
        assert_eq!(best_match(&[], &[1.0]), None);
    }

    #[test]
    fn personal_threshold_uses_the_least_similar_pair_of_one_model() {
        let unit = |deg: f32| {
            let r = deg.to_radians();
            vec![r.cos(), r.sin()]
        };
        // Model 0: samples 0°, 20°, 40° (least similar pair: cos 40° ≈ 0.766).
        // Model 1 is far away; pairs across models do not count.
        let known = vec![
            (0, unit(0.0)),
            (0, unit(20.0)),
            (0, unit(40.0)),
            (1, unit(170.0)),
        ];
        let t = personal_threshold(&known).unwrap();
        assert!(
            (t - (40f32.to_radians().cos() - PERSONAL_MARGIN)).abs() < 1e-5,
            "{t}"
        );
        // Near-identical samples hit the cap.
        let tight = vec![(0, unit(0.0)), (0, unit(1.0))];
        assert_eq!(personal_threshold(&tight), Some(PERSONAL_CAP));
        // No pair within one model: nothing to derive.
        assert_eq!(personal_threshold(&[(0, unit(0.0)), (1, unit(5.0))]), None);
        assert_eq!(personal_threshold(&[]), None);
    }
}
