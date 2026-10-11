# Recognition thresholds

`min_similarity` controls how closely a face must match. Higher values reject
more strangers but can also reject more genuine users.

These measurements use **LFW press photos**, not webcam or infrared logins.
They do not measure video replays, masks, twins or look-alikes.

## Results

**FAR:** strangers accepted. **FRR:** genuine attempts rejected.
A five-sample model matches the best of its five enrolled photos.

| Threshold | FAR: one photo | FRR: one photo | FAR: five samples | FRR: five samples |
|---:|---:|---:|---:|---:|
| 0.25 | 3.5% | 0.05% | 10% | 0.05% |
| 0.30 | 0.89% | 0.08% | 3.0% | 0.05% |
| 0.33 | 0.34% | 0.12% | 1.3% | 0.05% |
| **0.363 (default)** | **0.11% (1 in 930)** | 0.19% | **0.42% (1 in 240)** | 0.13% |
| 0.40 | 0.027% | 0.36% | 0.11% (1 in 900) | 0.16% |
| **0.45 (Secure)** | 0.0042% | 0.92% | **0.018% (1 in 5,700)** | 0.53% |
| 0.50 (personal cap) | 0.00064% | 2.4% | 0.0020% (1 in 51,000) | 1.4% |
| 0.55 | 0.00016% | 5.9% | 0.00027% | 3.9% |
| 0.60 | 0.00010% | 14% | 0.00010% | 6.4% |
| 0.70 | 0.00006% | 53% | 0.00007% | 32% |

## Choosing a setting

- **Secure** uses 0.45 and enables the personal threshold for stricter matching.
- More enrolled samples or models give strangers more opportunities to match.
- Head turns help against still photos, but a stranger can follow them too.
- The personal threshold only raises the configured threshold, up to 0.50.
  It increased thresholds for 11% of LFW subjects; FAR changed from 0.42% to 0.40%.
  Its effect on webcam enrollment has not been measured.
- Real login needs three matching frames. Frames are correlated: do not cube
  these error rates to estimate login security.

## How the measurements were made

- **Dataset:** 13,233 photos of 5,749 people from Hugging Face `bitmind/lfw`.
  Parquet SHA-256: `f0f046b07a3c59cc2bdaa218000948efc5c841b61e0e728022bd6274c3f5a69e`.
- **Pipeline:** OpenCV 4.13.0, shipped YuNet and SFace models, detection score 0.6,
  NMS 0.3, images at most 320 px high, aligned faces, L2-normalized embeddings
  and cosine similarity.
- **Detection:** all photos produced a face. For 2,641 multi-face photos, the
  nearest face to the centre was used; real login skips multi-face frames.
- **Pairs:** 242,257 same-person and 87,307,271 different-person pairs.
- **Five-sample models:** 311 people had more than five photos. Five formed each
  model; remaining photos of that person were genuine attempts, and all photos
  of other people were stranger attempts.
- **Cross-check:** 99.2% accuracy at 0.363 on the standard 6,000-pair LFW protocol,
  compared with OpenCV's reported 99.40% for SFace.

Five different-person pairs scored at least 0.9, attributed to duplicate or
mislabelled photos. This limits interpretation of the smallest error rates.

The one-off evaluation script is not included. To repeat the results, use the
dataset and pipeline above, counting stranger scores at or above each threshold
as accepted and genuine scores below it as rejected.

## Check your own camera

Run `sudo peekin test` or use the app's **Test** page. For repeated timing tests:

```sh
cargo build --release -p peekin-cli --example benchmark
sudo target/release/examples/benchmark 20 "$USER"
```

These tools test your own recognition and timing, not stranger acceptance.
