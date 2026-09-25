# Match thresholds: measured error rates

How often does `min_similarity` let a stranger in, and how often does it turn
the right person away? This page reports measurements with the models PeekIn ships, and what they do not cover.

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
- **Tools:** a one-off evaluation with OpenCV 4.13 and the shipped models;
  the script is not part of the repository.

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
  model on a single frame. Raising `min_similarity` to **0.45** makes that
  about 1 in 5,700 while turning away 0.5% of genuine LFW attempts.
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
  other people's real faces. The head-movement check addresses photos; see the
  README's security section.
- **Webcams and infrared**: LFW is colour press photography. Genuine webcam
  scores, and infrared cameras, were not measured here.
- **Three frames**: a login needs three spaced frames matching the same model.
  For one impostor these frames are nearly identical, so the per-attempt
  stranger rate is probably close to the per-frame rate above, not its cube.

To measure your own genuine scores, run `sudo peekin test` a few times
(it prints the best similarity) or watch the Test tab.
