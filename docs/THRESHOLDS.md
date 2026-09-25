# Match thresholds: measured error rates

How often does `min_similarity` let a stranger in, and how often does it turn
the right person away? This page reports measurements with the models PeekIn
ships, and what they do not cover. Every figure comes from LFW press photos
compared with each other, not from webcam or infrared login attempts,
look-alikes or presentation attacks (photos, screens or masks held up to a
camera).

## Method

- **Data:** Labeled Faces in the Wild (LFW): 13,233 photos of 5,749 people,
  from the Hugging Face copy `bitmind/lfw` (parquet SHA-256
  `f0f046b07a3c59cc2bdaa218000948efc5c841b61e0e728022bd6274c3f5a69e`).
- **Pipeline:** the same as a login: YuNet detection (score 0.6, NMS 0.3,
  images scaled to at most 320 px high), SFace alignment and embedding,
  L2-normalised, cosine similarity; OpenCV 4.13.0, as on Fedora 44.
  Every photo produced a face. In 2,641 photos a second face was visible; the
  one nearest the centre was used (LFW photos are centred on their person;
  the app itself would skip such a frame).
- **Pairs:** all 242,257 pairs of photos of the same person and all 87,307,271
  pairs of different people.
- **Logins against a face model:** for the 311 people with more than 5 photos,
  5 photos form one face model (as enrollment does); every other photo of that
  person is a genuine attempt and every photo of anyone else an impostor
  attempt. A login matches the best of all enrolled samples, so this is the
  rate that matters.
- **Tools:** a one-off evaluation script with OpenCV 4.13 and the shipped
  models (`face_detection_yunet_2023mar.onnx`,
  `face_recognition_sface_2021dec.onnx`). The script is not part of the
  repository, so these figures cannot be re-run from it; see
  [Repeating the measurement](#repeating-the-measurement).

Sanity check: on the standard LFW protocol (6,000 pairs) the pipeline is 99.2%
accurate at 0.363. OpenCV reports 99.40% for SFace.

## Results

**FAR** = share of strangers accepted, **FRR** = share of genuine attempts
rejected.

| `min_similarity` | FAR, one photo each | FRR, one photo each | FAR, model of 5 samples | FRR, model of 5 samples |
|---:|---:|---:|---:|---:|
| 0.25 | 3.5 % | 0.05 % | 10 % | 0.05 % |
| 0.30 | 0.89 % | 0.08 % | 3.0 % | 0.05 % |
| 0.33 | 0.34 % | 0.12 % | 1.3 % | 0.05 % |
| **0.363** (default) | **0.11 %** (1 in 930) | 0.19 % | **0.42 %** (1 in 240) | 0.13 % |
| 0.40 | 0.027 % | 0.36 % | 0.11 % (1 in 900) | 0.16 % |
| 0.45 | 0.0042 % | 0.92 % | 0.018 % (1 in 5,700) | 0.53 % |
| **0.50** (personal cap) | 0.00064 % | 2.4 % | 0.0020 % (1 in 51,000) | 1.4 % |
| 0.55 | 0.00016 % | 5.9 % | 0.00027 % | 3.9 % |
| 0.60 | 0.00010 % | 14 % | 0.00010 % | 6.4 % |
| 0.70 | 0.00006 % | 53 % | 0.00007 % | 32 % |

Below about 1 in 10⁶ the rates stop falling: 5 of the 87 million "different
people" pairs score 0.9 or more, which are duplicate or mislabelled photos in
LFW rather than look-alikes.

## What this means

- **More samples, more chances for a stranger.** A login compares the face
  with every enrolled sample of every model; with 5 samples the stranger rate
  is about 4 times the single-photo rate, and several models (e.g. with and
  without glasses) raise it further in proportion.
- **At the default 0.363** roughly 1 stranger in 240 would match a 5-sample
  model on a single frame. Raising `min_similarity` to **0.45** (the settings
  app's Secure level, which also turns on the personal threshold) makes that
  about 1 in 5,700, at the cost of turning away 0.53% of genuine LFW attempts
  instead of 0.13%: about 4 times as many.
- **The head turns do not lower these rates.** They stop photos and still
  images, not people: a stranger in front of the camera can turn their head
  as asked, so at the default about 1 stranger in 240 still matches a
  5-sample model, with or without them. Only a higher threshold, or fewer
  enrolled samples, lowers that.
- **The personal threshold** (`[video] personal_threshold`) raises the
  threshold only when the enrolled samples are consistent. With LFW's varied
  photos that happened for 11% of people and barely changed the stranger rate
  (0.42% to 0.40%). Webcam samples from one enrollment session are far more
  alike, so for a real user it will probably reach its 0.50 cap: about 1
  stranger in 51,000 on this data.
- **FRR here is pessimistic.** LFW's genuine pairs are years apart, with
  different lighting, age and cameras. A login compares today's webcam image
  with a webcam enrollment, which scores much higher, so real rejections are
  expected to be rarer than these (not yet measured).

## What this does not cover

- **Relatives, twins and look-alikes**: LFW is mostly unrelated public
  figures. Close relatives will match more often than these rates.
- **Photos, screens, masks** (presentation attacks): these rates are about
  other people's real faces. The head-movement check stops photos and still
  images, not a video of the user switched to each turn as it is shown, or a
  mask; see
  the README's security section.
- **Webcams and infrared**: LFW is colour press photography. No webcam or
  infrared image was measured here, for genuine users or for strangers.
- **Three frames**: a login needs three spaced frames matching the same model.
  For one impostor these frames are nearly identical, so the per-attempt
  stranger rate is probably close to the per-frame rate above, not its cube.

## Repeating the measurement

The evaluation script is not in the repository. To repeat the LFW figures,
follow the method above: check the parquet's SHA-256, run every photo through
OpenCV's `FaceDetectorYN` and `FaceRecognizerSF` with the shipped models and
the pipeline settings listed, then count for each `min_similarity` the share
of impostor pairs or attempts scoring at or above it (FAR) and of genuine ones
scoring below it (FRR); a login accepts a score equal to the threshold.

The repository's own tools measure your face on your camera, not strangers:

- `sudo peekin test` prints the best similarity of a scan against your face
  models; run it a few times, or watch the settings app's Test tab.
- The `benchmark` example (`crates/peekin-cli/examples/benchmark.rs`) repeats
  `peekin test --until-match` and reports how many of your own attempts were
  accepted and how long they took:

  ```sh
  cargo build --release -p peekin-cli --example benchmark
  sudo target/release/examples/benchmark 20 "$USER"
  ```
