# Four checks before the reframing (run `full`, 5 seeds)

No setting was changed and no model of the main run was refitted. Checks 1, 2 and 4 re-read the saved
scores (`tools/fusion_checks.py` → `fusion_checks.json`); check 3 adds one supplementary run of the
MUEBA reimplementation without its keyword features (`tools/mueba_no_keywords.py` →
`mueba_no_keywords.json`; summary in `keywords_vs_labels.json`). Values are mean ± std over seeds 0–4
unless stated. Test period: 291 days, 210,551 sessions, 829 malicious; validation: 30 days, ~802
sessions per day. Budget B = 10/day → 2,910 test alerts intended.

---

## 1. Does "FLAITD behaves like AND at the budget" hold in every seed? — Yes

| Seed | τ_B | Other view must be ≥ | Test alerts | Alerts with a view < 0.95 | Share of FLAITD alerts that are also AND alerts | Jaccard(FLAITD, AND) | One-view-extreme malicious sessions* | …alerted |
|---|---|---|---|---|---|---|---|---|
| 0 | 0.839 | 0.953 | 2,629 | 0 | 83.9% | 0.73 | 9 | 0 |
| 1 | 0.837 | 0.952 | 2,645 | 0 | 81.5% | 0.70 | 10 | 0 |
| 2 | 0.840 | 0.954 | 2,563 | 0 | 86.3% | 0.72 | 11 | 0 |
| 3 | 0.837 | 0.952 | 2,681 | 0 | 83.2% | 0.72 | 12 | 0 |
| 4 | 0.837 | 0.952 | 2,730 | 0 | 82.9% | 0.71 | 11 | 0 |

\* malicious test sessions with one percentile score ≥ 0.99 and the other < 0.80.

All seeds tuned the same breakpoints (m = 0.80, h = 0.99). With them, an alert requires **both**
percentile scores ≥ ≈ 0.952; AND at the budget uses a common threshold of ≈ 0.963. FLAITD is therefore
a *graded AND*: its alert region is the AND corner with a slightly lower edge, and inside it the
sessions are ranked by the fuzzy risk. 82–86% of its alerts are also AND alerts. None of the 53
one-view-extreme malicious sessions (all seeds together) was alerted.

## 2. How many alerts per day would a one-view session need? — About 30 to 140

Budget (alerts per day on validation) at which τ_B falls low enough:

| Case | Needed budget (alerts/day) | Share of ~802 sessions/day |
|---|---|---|
| High in one view, Medium in the other (r ≤ 0.75) | 29.0–30.1 (≈ 3× B) | 3.7% |
| High in one view, Low in the other (r ≤ 0.50) | 137.7–140.6 (≈ 14× B) | 17.5% |
| The actual one-view-extreme malicious sessions (53 over 5 seeds) | min 38, median 86, max 141 | 5–18% |

At B = 10 the Medium/High rule consequents (r = 0.50 and 0.75) sit far below τ_B ≈ 0.84, so only the
"High ∧ High → VH" rule can produce alerts. The rule base would have to give one-view-extreme sessions
r ≈ 0.84 or more, or the budget would have to be 3–14 times larger. (Changing the rules now would be
tuning on test results; it can only be done with evaluation on another dataset.)

## 3. Does MUEBA's advantage come from labels or from keyword features? — Mostly labels

MUEBA's keyword features are `job_search` and `hacking_sites` (its Table 2), removed from both of its parts.

| Method | Keywords | PR-AUC | P@B | R@B | F1@B | Insiders (of 61) | Sc. 1 / 2 / 3 found | Alerts |
|---|---|---|---|---|---|---|---|---|
| MUEBA (reimpl.) | with | — | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6 | 15.4 / 27.0 / 5.2 | 3,053 |
| MUEBA (reimpl.) | without | — | 0.119 ± 0.007 | 0.448 ± 0.043 | 0.187 ± 0.006 | 46.4 | 17.0 / 23.8 / 5.6 | 3,147 |
| MUEBA LSTM part | with | 0.280 ± 0.021 | 0.103 | 0.566 | 0.173 | 47.8 | 15.4 / 27.0 / 5.4 | 4,787 |
| MUEBA LSTM part | without | 0.102 ± 0.012 | 0.100 | 0.497 | 0.165 | 47.2 | 17.0 / 24.2 / 6.0 | 4,159 |
| FLAITD | with | 0.031 ± 0.002 | 0.045 ± 0.004 | 0.144 ± 0.010 | 0.068 ± 0.005 | 46.0 | 24.4 / 15.6 / 6.0 | 2,650 |
| FLAITD | without | 0.021 ± 0.001 | 0.028 ± 0.001 | 0.085 ± 0.002 | 0.042 ± 0.001 | 37.2 | 23.0 / 8.2 / 6.0 | 2,506 |

- **At the budget, labels explain most of the gap.** Without keywords MUEBA keeps F1 0.187 (−15%);
  that is 4.5× FLAITD without keywords (0.042) and still 2.7× FLAITD with keywords (0.068).
- **For ranking, keywords matter a lot to MUEBA too.** Its classifier's PR-AUC falls from 0.280 to
  0.102 without them (−64%), but even then it is 5× FLAITD without keywords (0.021).
- **The two methods find different insiders.** MUEBA finds scenario 2 (job search + USB) far better
  (27.0 vs 15.6 of 30) but misses a third of scenario 1 (15.4 vs 24.4 of 25). FLAITD, which uses no
  labels in its detectors, finds almost every scenario-1 insider. Scenario 3: both find nearly all 6.
- MUEBA is trained on days 1–210, when 19 insiders have malicious sessions; 10 of them are also active
  in the test period. Check 5 shows that its advantage is not due to having seen these insiders.

## 4. Exact gap between the individual branch (I-only) and FLAITD

### At each method's own validation threshold (budget B = 10/day)

| Metric | I-only | FLAITD | FLAITD − I-only (per seed: 0 / 1 / 2 / 3 / 4) |
|---|---|---|---|
| PR-AUC | 0.042 ± 0.000 | 0.031 ± 0.002 | −0.010 / −0.010 / −0.012 / −0.013 / −0.014 |
| ROC-AUC | 0.867 | 0.890 | +0.027 / +0.024 / +0.021 / +0.018 / +0.022 |
| P@B | 0.023 | 0.045 | +0.023 / +0.027 / +0.024 / +0.018 / +0.018 |
| R@B | 0.163 | 0.144 | −0.018 / −0.002 / −0.017 / −0.030 / −0.030 |
| F1@B | 0.040 | 0.068 | +0.030 / +0.037 / +0.031 / +0.023 / +0.022 |
| Insiders found | 47.6 | 46.0 | −2 / −1 / −1 / −3 / −1 |
| Benign users alerted | 511 | 251 | −260 / −255 / −256 / −260 / −267 |
| Test alerts | 5,948 | 2,650 | −3,379 / −3,274 / −3,365 / −3,177 / −3,298 |

Seed-0 bootstrap (from RESULTS.md): PR-AUC(FLAITD) − PR-AUC(I-only) = −0.009, 95% CI [−0.025, 0.005],
P(diff ≤ 0) = 0.88.

### At equal alert volume (same number of test alerts for both)

| Volume | Method | Precision | Recall | Insiders |
|---|---|---|---|---|
| FLAITD's volume (2,563–2,730) | FLAITD | 0.040–0.050 | 0.133–0.160 | 45–47 |
| | I-only | 0.027–0.028 | 0.088 | 38 |
| I-only's volume (5,858–6,028) | FLAITD | 0.028–0.032 | 0.204–0.235 | 50 |
| | I-only | 0.022–0.023 | 0.162–0.164 | 47–48 |

### Precision in the top k test sessions (seed 0; other seeds agree within ±0.03)

| k | 10 | 50 | 100 | 291 (1/day) | 500 | 1,000 | 2,910 (budget) | 6,000 | 30,000 |
|---|---|---|---|---|---|---|---|---|---|
| I-only | 0.40 | 0.24 | 0.34 | 0.22 | 0.13 | 0.07 | 0.025 | 0.023 | 0.018 |
| FLAITD | 0.20 | 0.10 | 0.11 | 0.12 | 0.10 | 0.07 | 0.045 | 0.033 | 0.020 |

**Reading:** I-only is better at the very top of the ranking (its top 500 hold 64 malicious sessions,
53 of them scenario-1 after-hours sessions, against 49 for FLAITD); PR-AUC weights these ranks heavily,
hence I-only's higher PR-AUC. From about 1,000 alerts (≈ 3.4/day) onward FLAITD is more precise, and at
B = 10/day it has about twice the precision and half the benign users alerted. The crossover lies
between ≈ 1.7 and 3.4 alerts per day.

### Important qualification from the keyword-free run

| Method, without keywords | PR-AUC | P@B | R@B | F1@B | Insiders | Alerts |
|---|---|---|---|---|---|---|
| I-only | 0.035 ± 0.000 | 0.032 | 0.099 | 0.048 ± 0.001 | 40.2 | 2,576 |
| FLAITD | 0.021 ± 0.001 | 0.028 | 0.085 | 0.042 ± 0.001 | 37.2 | 2,506 |

Without the keyword features I-only stays on budget (2,576 alerts instead of 5,948) and beats FLAITD
on every metric. The budget overshoot of I-only, which gives FLAITD its precision advantage, is caused by
the keyword features: among benign sessions the share with a job-site visit rises from 12% (training)
to 20% (validation) and 26% (test), so a per-user model fitted on training drifts upward. FLAITD's
advantage over I-only at the budget therefore exists **only with the keyword features**. Also, I-only's
scores are almost identical across seeds (std ≤ 0.001): the predictor's training loss improves only
slightly on each user's mean. It still ranks sessions better than a plain per-user z-score (§7: PR-AUC
0.042 vs 0.028, bootstrap interval excludes 0), so it is not just a per-user distance.

---

# Three further analyses (`tools/extra_checks2.py` → `extra2.json`; no setting changed)

## 5. MUEBA on test insiders not seen in its training labels

"Seen" = the 19 insiders with at least one malicious session in days 1–210 (6 of scenario 1, 9 of
scenario 2, 4 of scenario 3). All their test sessions are removed: sessions under their accounts and
sessions they own (scenario 3 acts through a supervisor's account). Remaining: 210,215 test sessions,
687 malicious, 51 active insiders (24 / 21 / 6 per scenario). FLAITD and I-only keep their original
thresholds. Mean ± std over 5 seeds.

| Method | Test set | PR-AUC | P@B | R@B | F1@B | Insiders | Sc. 1 / 2 / 3 found |
|---|---|---|---|---|---|---|---|
| MUEBA (reimpl.) | all 61 insiders | — | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6 / 61 | 15.4 / 27.0 / 5.2 of 25 / 30 / 6 |
| MUEBA (reimpl.) | 51 unseen | — | 0.129 ± 0.011 | 0.556 ± 0.048 | 0.209 ± 0.015 | 39.0 / 51 | 14.4 / 19.4 / 5.2 of 24 / 21 / 6 |
| MUEBA LSTM part | 51 unseen | 0.285 ± 0.024 | 0.094 ± 0.020 | 0.611 ± 0.054 | 0.163 ± 0.030 | 39.2 / 51 | 14.4 / 19.4 / 5.4 |
| FLAITD | 51 unseen | 0.029 ± 0.002 | 0.042 ± 0.003 | 0.160 ± 0.010 | 0.066 ± 0.005 | 41.6 / 51 | 23.4 / 12.2 / 6.0 |
| I-only | 51 unseen | 0.045 ± 0.000 | 0.021 ± 0.000 | 0.181 ± 0.001 | 0.038 ± 0.000 | 43.6 / 51 | 24.0 / 13.6 / 6.0 |

- MUEBA's session-level lead survives almost unchanged on insiders it never saw (F1 0.209 vs 0.221;
  classifier PR-AUC 0.285 vs 0.280). It does not memorise individual insiders: it learns the scripted
  scenario *types*, which recur across insiders in CERT.
- Its training labels are dominated by scenario 2 (167 of 201 malicious sessions in days 1–210; 14 of
  scenario 1, 20 of scenario 3), which matches its pattern: 19.4 of 21 unseen scenario-2 insiders
  found, but only 14.4 of 24 scenario-1.
- At the insider level, the label-free methods find **more** unseen insiders than MUEBA
  (FLAITD 41.6, I-only 43.6, MUEBA 39.0 of 51), because they catch almost all of scenario 1.

## 6. Union of MUEBA and FLAITD alerts

| Alerts | P@B | R@B | F1@B | Insiders (of 61) | Sc. 1 / 2 / 3 (of 25 / 30 / 6) | Test alerts | Benign users alerted |
|---|---|---|---|---|---|---|---|
| MUEBA | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6 ± 1.5 | 15.4 / 27.0 / 5.2 | 3,053 | 118 |
| FLAITD | 0.045 ± 0.004 | 0.144 ± 0.010 | 0.068 ± 0.005 | 46.0 ± 0.6 | 24.4 / 15.6 / 6.0 | 2,650 | 251 |
| MUEBA ∪ FLAITD | 0.086 ± 0.004 | 0.568 ± 0.042 | 0.149 ± 0.007 | **59.0 ± 0.6** | 25.0 / 28.0 / 6.0 | 5,481 | 287 |

Insiders found by both: 34.6; by MUEBA only: 13.0; by FLAITD only: 11.4 (means over seeds). The union
finds 59 of 61 insiders, including every scenario-1 and scenario-3 insider, but raises about 18.8
alerts per day, i.e. roughly twice the budget; it is not budget-matched to either method.

## 7. Per-user z-score baseline

Same 14 features, standardised per user exactly as the individual branch (clean training sessions,
floors 0.1 × global std and 0.1), score = mean of z²; ECDF on validation and budget threshold as for
I-only. It has no random component, so one run is reported (no std).

| Method | Features | PR-AUC | ROC-AUC | P@B | R@B | F1@B | Insiders | Sc. 1 / 2 / 3 | Alerts | Benign users |
|---|---|---|---|---|---|---|---|---|---|---|
| Per-user z-score | 14 | 0.028 | 0.849 | 0.027 | 0.306 | 0.050 | 48 | 24 / 18 / 6 | 9,314 | 478 |
| I-only (LSTM) | 14 | 0.042 ± 0.000 | 0.867 | 0.023 | 0.163 | 0.040 | 47.6 | 25 / 16.6 / 6 | 5,948 | 511 |
| FLAITD | 14 | 0.031 ± 0.002 | 0.890 | 0.045 | 0.144 | 0.068 | 46.0 | 24.4 / 15.6 / 6 | 2,650 | 251 |
| Per-user z-score | 11 (no K) | 0.031 | 0.829 | 0.033 | 0.103 | 0.050 | 42 | 25 / 11 / 6 | 2,557 | 559 |
| I-only (LSTM) | 11 (no K) | 0.035 ± 0.000 | 0.867 | 0.032 | 0.099 | 0.048 | 40.2 | 25 / 9.2 / 6 | 2,576 | 478 |
| FLAITD | 11 (no K) | 0.021 ± 0.001 | 0.877 | 0.028 | 0.085 | 0.042 | 37.2 | 23 / 8.2 / 6 | 2,506 | 235 |

Seed-0 paired bootstrap over users (1,000 resamples): PR-AUC(I-only) − PR-AUC(z-score) = +0.014,
95% CI [0.004, 0.025], P(diff ≤ 0) = 0.001; PR-AUC(FLAITD) − PR-AUC(z-score) = +0.005,
[−0.009, 0.017], P = 0.20. Spearman correlation of z-score and I-only test scores: 0.90.

- The attention-LSTM adds real ranking value over a plain per-user z-score with all 14 features
  (+0.014 PR-AUC, significant), although the two rankings are highly correlated.
- FLAITD is not distinguishable from the z-score baseline on PR-AUC.
- The z-score overshoots the budget even more than I-only (9,314 alerts, 3.2×), again only with the
  keyword features.
- Without keyword features, the z-score is as good as or better than every label-free method at the
  budget (F1 0.050 vs 0.048 I-only and 0.042 FLAITD) and finds the most insiders (42).

## 8. Budget-matched union: 5 alerts per day each

`tools/union_budget.py` → `union_budget.json`; no setting changed. Each method gets 5 alerts per day,
with its threshold set on the validation period exactly like τ_B; the test alerts of the two are
combined. MUEBA has no continuous output, so its score is min(p_LSTM, s_iForest): thresholding this at
0.5 reproduces MUEBA's own AND rule. Mean ± std over 5 seeds; 291 test days.

| Alerts | Precision | Recall | F1 | Insiders (of 61) | Sc. 1 (of 25) | Sc. 2 (of 30) | Sc. 3 (of 6) | Test alerts (per day) | Benign users |
|---|---|---|---|---|---|---|---|---|---|
| MUEBA, 5/day | 0.209 ± 0.012 | 0.272 ± 0.011 | 0.236 ± 0.010 | 44.8 ± 1.3 | 15.2 ± 1.2 | 24.6 ± 1.5 | 5.0 ± 0.6 | 1,082 (3.7) | 89 |
| FLAITD, 5/day | 0.063 ± 0.002 | 0.099 ± 0.004 | 0.077 ± 0.003 | 39.8 ± 0.7 | 22.8 ± 0.7 | 11.6 ± 0.8 | 5.4 ± 0.5 | 1,308 (4.5) | 162 |
| **Union (5 + 5)** | 0.116 ± 0.004 | 0.319 ± 0.012 | 0.170 ± 0.006 | **56.6 ± 1.5** | 24.6 ± 0.5 | 26.0 ± 1.3 | 6.0 ± 0.0 | 2,276 (7.8) | 202 |
| *Reference:* MUEBA, native rule | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6 ± 1.5 | 15.4 | 27.0 | 5.2 | 3,053 (10.5) | 118 |
| *Reference:* FLAITD, 10/day | 0.045 ± 0.004 | 0.144 ± 0.010 | 0.068 ± 0.005 | 46.0 ± 0.6 | 24.4 | 15.6 | 6.0 | 2,650 (9.1) | 251 |

Overlap (means): 113 test alerts shared; insiders found by both 28.0, by MUEBA only 16.8, by FLAITD
only 11.8. Validation thresholds: MUEBA min-score 0.591–0.605, FLAITD risk 0.875–0.877.

- With fewer test alerts than either method alone at 10/day (2,276 vs 3,053 and 2,650), the union finds
  56.6 of 61 insiders, against 47.6 for MUEBA and 46.0 for FLAITD: every scenario-3 insider, 24.6 of 25
  in scenario 1 and 26.0 of 30 in scenario 2.
- Its session-level precision (0.116) and recall (0.319) are below MUEBA's native rule (0.141, 0.517):
  the union trades session coverage for insider coverage.
- Both methods raise fewer test alerts than their 5/day share (3.7 and 4.5 per day). For MUEBA this is
  expected: its classifier was fitted on days 1–210, including the validation month used to set the
  threshold.

---

# Post-hoc analyses added after the freeze (2026-09-28)

Requested by the author after the analysis freeze; `tools/posthoc_after_freeze.py` → `posthoc.json`.
Saved scores only: no retraining, no setting changed. Mean ± std over seeds 0–4.

## 9. Fuzzy-MUEBA: MUEBA's two parts fused by the FLAITD fuzzy system

MUEBA's part scores (classifier probability p_LSTM, iForest score s_iForest) are ECDF-normalised on the
validation period, fused by the same Mamdani system (breakpoints chosen on validation PR-AUC from the
same grid), and alerted at τ_B for 10 alerts per day. Compared with MUEBA's own rule (both parts > 0.5).
**Caveat:** MUEBA's classifier is fitted on days 1–210, so its validation scores are in-sample; the
ECDF, the breakpoint choice and τ_B all rest on data the classifier was trained on. This is why
Fuzzy-MUEBA raises fewer test alerts than intended (2,123 vs 2,910).

| Method | PR-AUC | ROC-AUC | P@B | R@B | F1@B | Insiders (of 61) | Sc. 1 / 2 / 3 (of 25 / 30 / 6) | Benign users | Alerts |
|---|---|---|---|---|---|---|---|---|---|
| MUEBA, AND rule | — | — | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6 ± 1.5 | 15.4 / 27.0 / 5.2 | 118 ± 19 | 3,053 ± 317 |
| Fuzzy-MUEBA | 0.159 ± 0.012 | 0.933 ± 0.010 | 0.152 ± 0.007 | 0.390 ± 0.018 | 0.219 ± 0.010 | 48.8 ± 0.4 | 18.6 / 25.0 / 5.2 | 150 ± 12 | 2,123 ± 25 |
| *Reference:* MUEBA classifier part alone | 0.280 ± 0.021 | 0.891 ± 0.028 | 0.103 ± 0.021 | 0.566 ± 0.046 | 0.173 ± 0.030 | 47.8 ± 1.5 | 15.4 / 27.0 / 5.4 | 128 ± 18 | 4,787 ± 1,151 |
| *Reference:* FLAITD | 0.031 ± 0.002 | 0.890 ± 0.003 | 0.045 ± 0.004 | 0.144 ± 0.010 | 0.068 ± 0.005 | 46.0 ± 0.6 | 24.4 / 15.6 / 6.0 | 251 ± 4 | 2,650 ± 55 |

Breakpoints chosen: m = 0.90, h = 0.99 in every seed; τ_B = 0.712–0.722.

- Replacing MUEBA's AND rule by the fuzzy system leaves F1 at the budget unchanged (0.219 vs 0.221) and
  gives a slightly higher precision (0.152 vs 0.141) and 1.2 more insiders found (48.8 vs 47.6, mostly
  scenario 1: 18.6 vs 15.4), at lower session recall (0.390 vs 0.517) and with 30% fewer alerts.
- Fuzzy fusion again ranks worse than the stronger part alone: PR-AUC 0.159 vs 0.280 for MUEBA's
  classifier, the same pattern as FLAITD vs I-only (0.031 vs 0.042).

## 10. Calibration of FLAITD's risk levels

Share of malicious sessions per output level (the output term with the highest membership at r), each
seed with its own breakpoints (m = 0.80, h = 0.99). Base rate: 0.65% (validation), 0.39% (test).

| Level | Val sessions | Val malicious | Val share | Val lift | Test sessions | Test malicious | Test share | Test lift | Share of all test malicious |
|---|---|---|---|---|---|---|---|---|---|
| VL | 12,330 ± 44 | 2.0 ± 0.6 | 0.02% | 0.03× | 105,153 ± 402 | 4.0 ± 0.6 | 0.004% | 0.01× | 0.5% |
| L | 5,665 ± 59 | 11.4 ± 1.5 | 0.20% | 0.3× | 46,645 ± 388 | 63.2 ± 4.5 | 0.14% | 0.35× | 7.6% |
| M | 3,413 ± 43 | 45.6 ± 2.6 | 1.34% | 2.1× | 32,680 ± 227 | 220.6 ± 9.6 | 0.68% | 1.7× | 26.6% |
| H | 2,501 ± 35 | 75.0 ± 2.5 | 3.00% | 4.6× | 24,738 ± 210 | 458.4 ± 9.2 | 1.85% | 4.7× | 55.3% |
| VH | 153 ± 2 | 22.0 ± 1.1 | 14.4% | 22× | 1,335 ± 27 | 82.8 ± 3.7 | 6.20% | 16× | 10.0% |
| all | 24,062 | 156 | 0.65% | 1× | 210,551 | 829 | 0.39% | 1× | 100% |

- The levels are well ordered on both periods: the share of malicious sessions rises monotonically from
  VL to VH, and the lift over the base rate is almost the same on validation and test for L, M and H.
- They are not probabilities: even VH holds only 6.2% malicious sessions on test (14.4% on validation),
  and the absolute shares fall from validation to test because the test base rate is lower.
- VL (half of all sessions) contains 0.5% of the malicious test sessions; H and VH together contain
  65% of them, in 12% of the sessions.
- The VH level holds about 4.6 test sessions per day, H about 85 per day, so at B = 10/day the alerts
  are the VH sessions plus the top of H.

## 11. Budget sweep (post-hoc, descriptive)

Added 2026-09-29, after the freeze; `tools/budget_sweep.py` → `budget_sweep.json`,
`fig_budget_sweep.png`. Saved scores only; no retraining, no setting changed. For each budget B the
threshold is set on the validation period as τ_B and applied to the test period. AND uses one common
percentile, bisected for B alerts per day. MUEBA is thresholded on min(p_LSTM, s_iForest), so at a
budget it is *not* its native rule (at B = 10 it gives 47.0 insiders and precision 0.169, against 47.6
and 0.141 for the native rule). MUEBA+FLAITD = union of each at B/2. Mean over seeds 0–4; the
largest std of the insider counts in the table is 2.7.

**Test insiders found (of 61)**

| Method | B=1 | B=2 | B=3 | B=5 | B=10 | B=15 | B=20 | B=30 | B=50 |
|---|---|---|---|---|---|---|---|---|---|
| FLAITD | 25.6 | 25.6 | 32.2 | 39.8 | 46.0 | 47.4 | 49.4 | 53.0 | 59.8 |
| I-only | 25.0 | 30.0 | 32.8 | 38.0 | 47.6 | 49.0 | 49.0 | 52.6 | 60.0 |
| G-only | 7.0 | 13.6 | 17.4 | 23.0 | 32.0 | 37.4 | 41.6 | 48.8 | 54.6 |
| AND | 16.2 | 25.2 | 32.4 | 39.0 | 46.2 | 48.2 | 51.2 | 56.2 | 59.8 |
| Mean | 16.4 | 28.0 | 33.8 | 40.6 | 46.0 | 48.2 | 48.4 | 55.6 | 60.0 |
| MUEBA (min-score) | 23.6 | 32.4 | 39.2 | 44.8 | 47.0 | 48.0 | 48.6 | 50.4 | 53.2 |
| MUEBA+FLAITD (B/2 each) | 32.4 | 37.6 | 39.4 | 45.8 | 56.6 | 58.0 | 58.6 | 59.0 | 60.0 |

**Precision (test sessions)**

| Method | B=1 | B=2 | B=3 | B=5 | B=10 | B=15 | B=20 | B=30 | B=50 |
|---|---|---|---|---|---|---|---|---|---|
| FLAITD | 0.110 | 0.110 | 0.083 | 0.063 | 0.045 | 0.036 | 0.031 | 0.025 | 0.023 |
| I-only | 0.327 | 0.146 | 0.047 | 0.025 | 0.023 | 0.022 | 0.023 | 0.021 | 0.019 |
| G-only | 0.043 | 0.046 | 0.046 | 0.040 | 0.027 | 0.021 | 0.020 | 0.019 | 0.018 |
| AND | 0.154 | 0.118 | 0.082 | 0.064 | 0.048 | 0.039 | 0.034 | 0.029 | 0.024 |
| Mean | 0.169 | 0.121 | 0.086 | 0.062 | 0.046 | 0.038 | 0.032 | 0.028 | 0.024 |
| MUEBA (min-score) | 0.362 | 0.290 | 0.240 | 0.209 | 0.169 | 0.137 | 0.111 | 0.074 | 0.043 |
| MUEBA+FLAITD (B/2 each) | 0.121 | 0.144 | 0.161 | 0.150 | 0.116 | 0.098 | 0.087 | 0.070 | 0.046 |

**Actual test alerts per day** (the intended value is B)

| Method | B=1 | B=2 | B=3 | B=5 | B=10 | B=15 | B=20 | B=30 | B=50 |
|---|---|---|---|---|---|---|---|---|---|
| FLAITD | 1.5 | 1.5 | 2.6 | 4.5 | 9.1 | 13.9 | 18.8 | 30.9 | 51.9 |
| I-only | 0.5 | 1.5 | 4.9 | 10.0 | 20.4 | 27.4 | 33.0 | 44.5 | 68.8 |
| G-only | 0.6 | 1.3 | 2.1 | 3.6 | 7.8 | 12.6 | 17.5 | 27.6 | 47.5 |
| AND | 0.6 | 1.4 | 2.6 | 4.5 | 9.1 | 14.0 | 19.1 | 29.5 | 49.1 |
| Mean | 0.5 | 1.5 | 2.6 | 4.6 | 9.1 | 13.9 | 18.9 | 29.6 | 50.6 |
| MUEBA (min-score) | 0.4 | 1.2 | 2.1 | 3.7 | 7.1 | 10.9 | 14.6 | 23.7 | 44.2 |
| MUEBA+FLAITD (B/2 each) | 1.6 | 1.8 | 2.1 | 3.5 | 7.8 | 11.7 | 15.5 | 23.8 | 41.4 |

- FLAITD is identical at B = 1 and 2 because its risk saturates at 0.918, the value when both views are
  fully High. In seed 0, 64 validation sessions (2.1 per day) share that value, so both budgets give
  the same threshold. The fuzzy output cannot rank sessions inside this plateau.
- FLAITD, AND and Mean are within about 2 insiders and 0.01 precision of each other from B = 3 upward,
  so the graded-AND behaviour holds across budgets, not only at B = 10. At B = 1–2, Mean and AND are
  more precise than FLAITD (0.169 and 0.154 against 0.110 at B = 1).
- I-only's overshoot starts at B = 3 (4.9 alerts per day for an intended 3) and grows to about 2×. At
  B = 1–2, where it stays within budget, it is the most precise label-free method (0.327 at B = 1).
- The union finds the most insiders at every budget. MUEBA alone has the highest precision up to
  B = 20, and it finds fewer insiders than the label-free methods from B = 20 upward (53.2 against
  about 60 at B = 50).

---

## What this means for the evaluation framing (facts only)

1. Under a fixed analyst budget, a Mamdani fusion whose weaker consequents lie below the budget
   threshold acts as a graded AND (check 1); letting one-view sessions through needs a 3–14× larger
   budget (check 2).
2. The strongest method is the supervised one; its lead is mostly due to labels, not to keywords, and
   it finds a different mix of scenarios (check 3).
3. FLAITD vs its own individual branch depends on the operating point and on the keyword features:
   I-only ranks the top few hundred sessions better; FLAITD is more precise at 10 alerts/day with
   keywords; without keywords I-only is better throughout (check 4).
4. MUEBA's lead is not memorisation of seen insiders; its labels teach it the scripted scenario types,
   mostly scenario 2. Label-free methods still find more unseen insiders, mostly through scenario 1
   (check 5).
5. MUEBA and FLAITD are complementary at the insider level: together they find 59 of 61 insiders, at
   twice the alert volume (check 6).
6. A plain per-user z-score is a strong baseline: the LSTM beats it on ranking, FLAITD does not, and
   without keywords it matches or beats every label-free method at the budget (check 7).
7. Splitting the budget, 5 alerts per day each, the union of MUEBA and FLAITD finds 56.6 of 61
   insiders with 7.8 alerts per day, more than either method with the full budget (check 8).
