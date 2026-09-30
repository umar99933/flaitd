# Preregistration: FLAITD confirmation run on CERT r5.2

**Written:** 2026-09-29 16:53 UTC, before any r5.2 file was downloaded, extracted or read. The r5.2
answer key (`data/answers/r5.2-*`, the r5.2 rows of `insiders.csv`) has not been opened.
**Code state:** the git commit that adds this file. Its hash and time are the registration record.
**Authors:** Umer Farooq, Ch Anwar Ul Hassan.
**Amendment 1:** 2026-09-30 16:47 UTC, still before any r5.2 file was downloaded or read. It changes
H1 (margin and test) and H3 (budgets), adds the Jaccard overlap as a descriptive measure, and adds an
owner-crediting check to step 1. Amended passages are marked *[A1]*. The version before the amendment
is the registration commit `ef62de7`.

## 1. Purpose

The r4.2 study (`results/full/RESULTS.md`, `results/full/extra/CHECKS.md` §1–12) was exploratory: the
fusion analyses were designed after its test results had been seen. This run tests three findings from
r4.2 once, on a release that has not been inspected, with everything fixed in advance. Nothing in this
run changes the r4.2 results.

## 2. Data

- **Release:** CERT Insider Threat Test Dataset r5.2 (Lindauer 2020, doi:10.1184/R1/12841247),
  `r5.2.tar.bz2` from KiltHub. Its SHA-256 must equal
  `9a7fadba71482474e8a2a7dddbf3620d450796d0059526db3362d41096d0f5bf` (published CHECKSUMS-sha256.txt);
  otherwise the file is re-downloaded.
- **Answer key:** `answers.tar.bz2`, already verified (SHA-256
  `ed21bf92…efa52fa3`), folders `r5.2-1` … `r5.2-4`.
- **Users:** all users (`users.mode: all`). No sampling.

## 3. Frozen pipeline

- **Code and settings** are those of `config/default.yaml` and `flaitd/` at the registration commit:
  - session rules, including the screen-unlock merge;
  - the 14 features, the keyword lists and the three excluded hosts;
  - all model hyperparameters, the ECDF normalisation and the breakpoint grid with its
    validation-PR-AUC rule;
  - the MUEBA reimplementation and every other baseline.
- **The only permitted additions** before labels are used:
  1. `config/r52.yaml`, which sets only `run_name: r52`, `data_dir: data/r5.2`,
     `dataset_version: "5.2"`, `cache_dir: cache/r52` and `results_dir: results/r52`;
  2. the FLAITD-tb scoring function (§6) with a unit test on synthetic arrays;
  3. a generalisation of `tools/budget_sweep.py` / `tools/budget_ci.py` to any number of test
     insiders and to FLAITD-tb, plus *[A1]* the 90% CIs for H1 and the Jaccard overlap (§6).

  All three are committed before `run.py prepare` is run on r5.2. They are not evaluated on r4.2.
- **Data problems:** `run.py check` and the data audit may lead only to fixes of paths, file formats or
  parsing errors, each shown to the authors and logged in `CHANGES.md` under "r5.2 deviations". No
  finding of the audit changes the split, the keyword lists, the excluded hosts or any setting. A
  keyword list that fires unusually often or never on r5.2 is reported, not edited.

## 4. Split, seeds and budgets

- **Split:** day 1 = first day present in `logon.csv`. Training = days 1–180, validation = days 181–210,
  test = day 211 to the last day in the data. These are the same day numbers as on r4.2, fixed
  regardless of how insider activity falls. If validation holds fewer than 10 malicious sessions, the
  existing rule applies (default breakpoints m = 0.85, h = 0.97; stacking by grouped CV) and is reported.
  The split is not moved.
- **Seeds:** 0, 1, 2, 3, 4 for every stochastic component.
- **Budgets:** B ∈ {1, 3, 10, 30} alerts per day, threshold set on the validation period exactly as τ_B
  (`metrics.budget_threshold`). **B = 10 is primary.**

## 5. Methods compared at each budget

| Method | Definition (as in CHECKS.md §11) |
|---|---|
| FLAITD | fuzzy risk r |
| I-only, G-only | percentile scores of the two branches |
| AND | one common percentile q for both branches, bisected for B alerts per day on validation |
| Mean | (s̃^I + s̃^G) / 2 |
| MUEBA | min(p_LSTM, s_iForest), thresholded for B; its native rule (both > 0.5) is also reported |
| MUEBA+FLAITD | union of MUEBA and FLAITD alerts, each thresholded separately on validation for B/2 alerts per day; an alert raised by both counts once |

The single methods for H2 and H3 are FLAITD, I-only, G-only, AND, Mean and MUEBA.

## 6. Metrics and statistics

- **Test insiders found:** insiders with at least one alerted malicious test session, crediting
  sessions to the owning insider (scenario-3-type sessions under another account count for the insider).
- **Session precision:** alerted malicious test sessions / all alerted test sessions.
- **Also reported, not tested:** user-level precision (insiders found / (insiders found + benign users
  alerted)), recall, F1, test alerts per day, PR-AUC and ROC-AUC where defined, and results per
  scenario.
- *[A1]* **Alert overlap, descriptive:** the Jaccard index of the sets of alerted test sessions,
  |A ∩ B| / |A ∪ B|, for FLAITD vs AND and FLAITD vs Mean. It is computed per seed at every budget
  B ∈ {1, 3, 10, 30} and reported as the mean over seeds, with its range.
- **Pooling:** each metric is the mean over the five seeds.
- **Bootstrap:**
  - Resample the test insiders with replacement, 1,000 resamples, NumPy `default_rng(0)`, keeping
    benign sessions fixed.
  - A resampled insider brings its detection indicator and its alerted malicious sessions.
  - In each replicate, compute the metric per seed with the same resample and average over seeds.
  - Differences are paired within replicates; intervals are the 2.5th and 97.5th percentiles.
  - This is the procedure of `tools/budget_ci.py`.
- **Multiplicity:** three primary hypotheses, each with its own decision rule; no correction. Every
  hypothesis is reported whatever its outcome.

## 7. Primary hypotheses and decision rules (B = 10 unless stated)

**H1 (graded AND), *[A1]* equivalence test.** FLAITD and AND find the same number of test insiders
within a margin δ.
- **Margin.** δ = 5% of N, where N is the number of r5.2 test insiders (insiders with at least one
  malicious test session). It is rounded to the nearest integer, with halves rounded up, and is at
  least 2: δ = max(2, ⌊0.05·N + 0.5⌋). N is counted in step 2, before any model is scored; δ is
  written into `CHANGES.md` at that point.
- **Statistic.** D1 = insiders(FLAITD) − insiders(AND), with paired bootstrap CIs (§6).
- *Supported* if the **90%** CI (two one-sided tests at α = 0.05) lies within [−δ, +δ].
- *Rejected* if the **95%** CI lies entirely outside [−δ, +δ], that is, above +δ or below −δ.
- *Inconclusive* otherwise.

The point estimate of D1, both intervals and the session-precision difference are also reported.

**H2 (complementarity).** The MUEBA+FLAITD union finds more test insiders than each of the six single
methods. For each single method k, let D2_k = insiders(union) − insiders(k), with CI [L_k, U_k].
- *Supported* if L_k > 0 for all six.
- *Rejected* if U_k < 0 for at least one k.
- *Inconclusive* otherwise.

**H3 (supervised precision).** *[A1]* MUEBA has the highest session precision at B ∈ {3, 10}, against
the five other single methods and the union. For each B and each other method k, let
D3_{B,k} = precision(MUEBA) − precision(k), with 95% CI [L, U].
- *Supported* if L > 0 for all **12** comparisons.
- *Rejected* if U < 0 for at least one.
- *Inconclusive* otherwise.

B = 1 is reported descriptively only, with the same differences and CIs. At B = 1 several methods
cannot meet the budget because of ties (on r4.2, FLAITD raised 1.5 alerts per day), so the
comparison is not budget-matched.

## 8. Secondary, pre-specified variant: FLAITD-tb

**Motivation.** On r4.2 the fuzzy risk saturates at 0.9183 (only the VH rule firing, at full strength).
About 2 validation sessions per day share that value, so budgets below about 2 per day cannot be met
(CHECKS.md §12). FLAITD-tb breaks ties in the defuzzified score by the mean of the two ECDF inputs.

**Definition.**
- Sessions are ordered lexicographically by (r, (s̃^I + s̃^G) / 2), both descending.
- The validation threshold is the key of the ⌊B · N_val_days⌉-th validation session in that order
  (the same count as `budget_threshold`).
- A test session is alerted if its key is at least that key in lexicographic order.
- Risk levels and rule traces are unchanged.

**Reported** at B ∈ {1, 3, 10, 30}: test alerts per day, insiders found, session precision, and paired
bootstrap CIs of FLAITD-tb − FLAITD.

**Expectation (secondary, stated in advance).** At B = 1 and 3, FLAITD-tb's test alerts per day are
closer to B than FLAITD's, and its session precision at B = 1 is at least FLAITD's. This is reported
as a secondary result and does not count towards H1–H3. FLAITD-tb does not replace FLAITD in H1–H3.

## 9. Order of work and stop points

1. Download `r5.2.tar.bz2`, verify the SHA-256, extract, run `run.py check`. *[A1]* Also check that
   owner crediting covers every r5.2 scenario, including scenario 4. Look at the answer-key **file
   structure only**:
   - the folder and file layout;
   - which log types (logon, device, file, email, http) occur in each scenario's files;
   - that every file's name carries the owning insider's user field, as the ingest code requires;
   - whether any scenario's events can occur under an account other than the file's owner.

   Report per scenario: file count, log types present, and whether events under another account
   occur (yes/no). Do not print or record user IDs, dates or event contents. If crediting would fail
   for a scenario, stop; any fix is a deviation (§10). **Stop:** report to the authors.
2. Commit the permitted additions (§3), then run `run.py --config config/r52.yaml prepare`. The audit
   uses labels only to verify event matching and session labelling. **Stop:** report the data
   summary and any warnings; no setting changes.
3. Run all methods, seeds 0–4. Then evaluate H1–H3 and FLAITD-tb with the frozen analysis scripts,
   in that order.
4. Write `results/r52/CONFIRMATION.md`: each hypothesis with its estimate, CI and verdict under §7,
   followed by the descriptive tables. Commit and push.

## 10. Deviations

Any departure from this document is recorded in `CHANGES.md` under "r5.2 deviations", with its reason
and whether it was made before or after r5.2 labels or test results were seen. It is disclosed in the
paper. If a deviation touches a setting that H1–H3 depend on after test results are seen, the affected
hypothesis is reported as not confirmatory.

## 11. Known limitations stated in advance

- r5.2 has a different organisation and more scenarios (the answer key has four r5.2 folders), so
  keyword lists written for r4.2 may fit it worse; that is part of what the run tests.
- MUEBA's classifier is trained on days 1–210, so its validation thresholds are set in-sample, as on
  r4.2.
- *[A1]* The H1 margin and test were changed in Amendment 1 after the r4.2 results had been seen, and
  the r4.2 CI informed the choice. Under the original rule (±2, 95% CI), r4.2 gives [−2.8, +2.0]:
  inconclusive. Under the amended rule, r4.2 gives δ = 3 of 61 test insiders (5% of 61 = 3.05) and a
  90% CI for FLAITD − AND at B = 10 of [−2.2, +1.6], which lies within [−3, +3]: supported (point
  estimate −0.2; `tools/budget_ci.py`, same 1,000 replicates as CHECKS.md §12). r4.2 is not a test of
  H1; it only shows what the rule gives on the data that motivated it. No r5.2 information was used.
