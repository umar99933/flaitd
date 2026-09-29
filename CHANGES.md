# Changes to the protocol

Every change to data stages, keyword lists, rules, breakpoints, windows or thresholds is recorded here
with its reason and when it was made relative to seeing any results.

## 1. Same-day repeat logons are screen unlocks (2026-09-26, Checkpoint 1)

**When:** after the data audit, before any model was trained or any test result computed.
Approved by the author at Checkpoint 1.

**Change:** a logon that follows a logon by the same user on the same PC on the same day, with no
logoff in between, continues the running session instead of starting a new one. Its malicious label (if
any) is carried to the session. Orphan repair (METHODOLOGY §3.2) is kept for any remaining logon without
a logoff. Config: `sessions.merge_unlocks: true`; code: `sessions._merge_unlocks`.

**Reason:** the r4.2 readme (`data/r4.2/readme.txt`, line 27) states: *"Screen unlocks are recorded as
logons. Screen locks are not recorded."* The first audit showed that all 86,340 "orphan" sessions (18.3%)
were the first part of a working day followed by a second logon on the same PC the same day and a
single logoff in the evening. Treating them as separate sessions cut one working session in two and
gave the second part an artificial mid-day logon hour. 125 malicious sessions were split this way.
No label was used to make this decision.

**Effect on data:** sessions 470,591 → see the rerun audit (expected 384,251, one per logoff).

## 2. Keyword matching on host and site section only; three unrelated hosts excluded (2026-09-26, Checkpoint 1)

**When:** after the data audit, before any model was trained or any test result computed.
Approved by the author at Checkpoint 1.

**Change:**
- Keyword terms are matched against the URL host (and, for terms written `/x` or `host/x`, the first
  path segment) instead of anywhere in the URL. Code: `ingest.keyword_hits`.
- `hotjobs` is written `/hotjobs`, the form in which it matched before (yahoo.com/hotjobs).
- New `features.keyword_exclude_hosts: [lifehacker.com, imageshack.us, cracked.com]`.
- No term was added to any list.

**Reason (label-free):** a scan of the hosts of all 28.4M web requests showed that in r4.2 the URL path
after the first segment is filler (an article title plus scrambled text), so whole-URL substring
matching fired by chance: `spy`, `malware` and `trojan` matched only in that filler, `crack` in
"crackdown" titles. The hacking list fired in 25% of sessions, almost entirely through lifehacker.com
(a tips blog), imageshack.us (an image host), cracked.com (a humour site) and filler text; by general
knowledge none of these is a hacking site. The job and leak lists already hit only job and
file-sharing hosts and are unchanged in content.

**Disclosure:** before this change was proposed, the author's assistant had seen (a) the audit's
per-scenario mean feature table, which is label-based, and (b) a few raw lines of answer-key files, as
CLAUDE.md step 3 asks, which show some scenario-specific hosts. For this reason the change only removes
matches on unrelated hosts and filler text and adds no term. Table VIII (no keyword features) shows
how much the keyword features contribute.

## 3. Constant training features are left unscaled in per-user standardisation (2026-09-26, step 4) — superseded by #4

**When:** during the first chunk debug run, before any metric was computed (the run was stopped before
its first `metrics.json` was written; no validation or test metric was looked at).

**Change:** in `seq.per_user_standardise` (individual branch and LSTM-AE baseline), a feature whose
standard deviation over the fitting rows is below 1e-6 gets mean-centred but unscaled (sd = 1) for every
user, as scikit-learn's `StandardScaler` does. Previously its sd fell to the absolute floor 1e-3.

**Reason:** after change #2, `n_hack` has no hit in clean training sessions. With sd = 1e-3 a single
keylogger visit in a later session became z ≈ 1,100; `n_hack` alone made up ~17 of the 18.7 mean squared
validation error of the predictor, so validation loss never fell and early stopping ended training after
4 epochs (log of the stopped chunk run). With the fix, mean z² is 0.54 (train) / 1.96 (validation) on
the chunk data. The individual score still reacts strongly to such a hit because residuals are divided
by their validation std σ_j (Eq. 5). The classic baselines already used `StandardScaler`; MUEBA fits
its scaler on days 1–210, where the feature is not constant, and is unchanged.

## 4. Absolute floor of 0.1 on every per-user standard deviation (2026-09-26, Checkpoint 2)

**When:** after the full-data seed-0 debug run. **Seed-0 test results had been seen** (validation and
test metrics in `results/full/RESULTS.md`, seed 0 only). Approved by the author at Checkpoint 2.
All five seeds are rerun from scratch with this change.

**Change:** `seq.per_user_standardise` (individual branch and LSTM-AE baseline) now uses
sd = max(user std, 0.1 × global std, `individual.min_std`) with `min_std = 0.1` in model units (log1p for
counts). This replaces both the former absolute floor (1e-3) and the constant-feature rule of #3.

**Reason (label-free):** the seed-0 log showed validation loss 6.37 for the ablation "training data not
cleaned" against 1.42 for the full model. In that ablation the few malicious June sessions stay in the
fitting rows, so `n_hack` has a tiny but non-zero std, escapes the #3 rule, and a single hit again
becomes z in the hundreds. Mean squared z over validation sessions, computed from features only (no
labels, no scores), was:

| rule | clean fit | not-cleaned fit |
|---|---|---|
| 1e-3 floor + #3 | 1.45 | 6.40 (`n_hack` alone 70) |
| min_std = 0.1 | 0.90 | 0.88 |

The value 0.1 is the existing relative floor factor reused in absolute units; with it one extra event
(log1p step 0.69) moves z by at most ~7, comparable to the largest values of ordinary features. It also
lowers the validation z² of `offhours` (1.42 → 0.35), `n_usb` (0.81 → 0.42) and `n_job` (9.4 → 3.8),
which were inflated in the same way for users who never showed them in training. No alternative value
was tried against test or validation metrics.

## Supplementary analyses after the final run (2026-09-27) — no setting changed

Added for the reframing as an evaluation paper; the main results in `results/full/` are unchanged.
- `tools/fusion_checks.py`: re-reads saved scores (AND-like behaviour per seed, budget needed for
  one-view sessions, I-only vs FLAITD at equal alert volume).
- `tools/mueba_no_keywords.py`: MUEBA reimplementation rerun for seeds 0–4 without `n_job`/`n_hack`
  (`run_mueba` got an optional `feats` argument; its default is unchanged).
Outputs and summary: `results/full/extra/` (`CHECKS.md`).
- `tools/extra_checks2.py` (2026-09-27): (1) MUEBA, FLAITD and I-only on test data restricted to the 51
  insiders without malicious sessions in days 1–210; (2) insider detection of the union of MUEBA and
  FLAITD alerts; (3) per-user z-score baseline (same 14 / 11 features, same per-user standardisation,
  mean z², evaluated like I-only). Reads saved scores; the z-score baseline is new and deterministic.
  Output `results/full/extra/extra2.json`, tables in `CHECKS.md` §5–7.
- `tools/union_budget.py` (2026-09-27): budget-matched union of MUEBA and FLAITD, 5 alerts per day each,
  thresholds set on the validation period as tau_B. MUEBA's continuous score for this analysis is
  min(p_lstm, s_iforest) (its AND rule at 0.5 is the special case). Reads saved scores only. Output
  `results/full/extra/union_budget.json`, table in `CHECKS.md` §8.

## ANALYSES FROZEN (2026-09-27)

At the author's request, no further analyses, settings or reruns. The numbers for the paper are
`results/full/RESULTS.md` (main tables, seeds 0–4) and `results/full/extra/CHECKS.md` §1–8
(supplementary analyses). Any later change must be recorded here with its reason and justified
independently of the results above.

## Post-hoc analyses added after the freeze (2026-09-28)

Requested by the author after the freeze. Saved scores only: no retraining, no setting changed, the
frozen results are unchanged. `tools/posthoc_after_freeze.py` → `results/full/extra/posthoc.json`,
tables in `CHECKS.md` §9–10.
1. Fuzzy-MUEBA: MUEBA's p_lstm and s_iforest ECDF-normalised on validation, fused by the same fuzzy
   system (breakpoints chosen on validation PR-AUC from the same grid), tau_B for 10 alerts/day;
   compared with MUEBA's AND rule. Caveat: MUEBA's validation scores are in-sample for its classifier.
2. Calibration: share of malicious sessions per FLAITD risk level (VL/L/M/H/VH) on validation and test.
- Budget sweep (2026-09-29, post-hoc, descriptive): `tools/budget_sweep.py`. For B = 1, 2, 3, 5, 10, 15,
  20, 30, 50 alerts/day, validation thresholds as tau_B; FLAITD, I-only, G-only, budget-matched AND, Mean,
  MUEBA (min-score) and the MUEBA+FLAITD union (B/2 each); test insiders, precision and alerts/day, mean
  over 5 seeds. Saved scores only, no setting changed. Table in `CHECKS.md` §11, figure
  `results/full/extra/fig_budget_sweep.png`.
