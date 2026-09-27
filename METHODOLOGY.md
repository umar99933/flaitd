# FLAITD — complete experimental methodology

This document is the run protocol for the paper *FLAITD: Interpretable Fuzzy Fusion of Individual and
Peer-Group Behaviour Models for Insider Threat Detection*. Every number in the paper's Results section
must come from following it end to end on CERT r4.2. The code in `flaitd/` implements each step exactly
as written here; section numbers in brackets refer to the paper.

---

## 0. Ground rules (read before running anything)

1. **The test period is touched only once, for evaluation.** Model fitting, score normalisation,
   alert thresholds, fuzzy breakpoints and every hyperparameter are decided on the training and
   validation periods only.
2. **Configuration is frozen before the final run.** If you change anything after looking at test
   results (keyword lists, window size, rules), record the change and the reason in `CHANGES.md`
   and rerun every seed. Never keep a change because it improved a test number.
3. **Keyword lists (`features.keywords`) are written from general knowledge, never from the answer
   key.** Table VIII reports results without them so readers can see how much they matter.
4. **Report what comes out.** If a baseline beats FLAITD on a metric, the paper says so. The fuzzy
   layer's value then rests on interpretability and label-free fusion, and the text must be adjusted.
5. **Five seeds** (0–4) for every stochastic component; tables show mean ± standard deviation.
6. **Chunk runs are for debugging only.** `config/chunk.yaml` keeps all insiders plus 200 benign
   users, which changes the base rate and the peer groups. Paper numbers come from `config/default.yaml`.

---

## 1. Data

* **Source:** CERT Insider Threat Test Dataset, release r4.2 (Lindauer, 2020, doi:10.1184/R1/12841247),
  files `r4.2.tar.bz2` and `answers.tar.bz2` from Carnegie Mellon's KiltHub repository.
* **Expected layout:**
  ```
  data/r4.2/logon.csv device.csv file.csv email.csv http.csv  LDAP/2009-12.csv … 2011-05.csv
  data/answers/insiders.csv  r4.2-1/  r4.2-2/  r4.2-3/  (other releases may be present; only 4.2 is used)
  ```
* **Pre-flight:** `python run.py check` verifies files, headers, the date format `MM/DD/YYYY HH:MM:SS`,
  LDAP columns and that every r4.2 answer file is present. Fix any reported problem before continuing.
* **Reference figures (MUEBA, for sanity only):** 1,000 users, 70 insiders, 502 days, 32,770,227 events
  of which 7,323 malicious, 341,794 sessions of which 993 malicious. Our session builder differs (screen
  unlocks, orphan repair, event assignment), so our counts will differ somewhat; report ours and note the
  difference. (Our event total is 32,770,222: MUEBA's figure evidently includes the five CSV header lines.)

## 2. Stage A — ingest (`flaitd/ingest.py`)

* Stream each CSV in chunks of `read_chunksize` rows; keep only `id, date, user, pc` plus:
  logon/device `activity`; file extension of `filename`; e-mail external-recipient flag
  (any address in `to/cc/bcc` outside `org_domain`) and attachment count; http keyword flags
  `job`, `hack`, `leak` (lowercase match of `features.keywords` against the URL host, or against the
  first path segment for terms written `/x` or `host/x`; hosts in `features.keyword_exclude_hosts` never
  match). The rest of an r4.2 URL path is filler text and is not searched (CHANGES.md #2).
* Every event whose id appears in an r4.2 answer file gets `mal = k`, where `k` is the 1-based row of
  the owning insider in `insiders.csv`; otherwise `mal = 0`.
* **Check:** `cache/<run>/ingest_meta.json → malicious_events_matched` should equal the number of ids
  in the answer files (7,323 for full r4.2 according to MUEBA). A large shortfall means an id-format or
  path problem.

## 3. Stage B — sessions (`flaitd/sessions.py`)  [IV-A]

1. Sort logon events by user, PC, time. A **session** starts at a Logon and ends at the next Logoff by
   the same user on the same PC. **Screen unlocks:** r4.2 records screen unlocks as logons (readme), so a
   Logon that follows a Logon by the same user on the same PC on the same day, with no Logoff in between,
   continues the running session; its label is carried to that session (CHANGES.md #1).
2. **Orphan logons** (next event for that user/PC is a Logon on a later day, or nothing) are closed at the last
   device/file/e-mail/web event on that PC before the next logon; if no such event exists, at
   `workday_end_hour` (19:00) on the same day, or 23:59:59 if the session started after 19:00. The end
   never exceeds the next logon.
3. Every session is capped at `max_duration_hours` (24 h).
4. Each device, file, e-mail and web event is assigned to the latest session of the same user and PC
   that started at or before it, provided the event is no later than the session end plus
   `event_grace_minutes` (60). Unassigned events are counted in `sessions_meta.json`.
5. **Label:** a session is malicious (`mal = 1`) if its logon, its logoff or any assigned event is
   malicious. `mal_owner` records the owning insider. This matters for scenario 3, where the insider
   acts under the supervisor's account: detections are credited to the insider, not the supervisor.
6. **Check:** `malicious_assigned` should be close to `malicious` for every event type.

## 4. Stage C — features and split (`flaitd/features.py`)  [IV-A, V-B]

**FLAITD features (14, Table I):** `duration_min, logon_hour, offhours, weekend, n_usb, n_file,
n_file_ext, n_email, n_email_ext, n_attach, n_http, n_job(K), n_hack(K), n_leak(K)`.
`offhours` = start before 07:00 or at/after 19:00. Counts and duration enter the models as log(1 + x).

**MUEBA features (10, its Table 2, numeric part):** `logon_hour, logoff_hour, duration_min, n_http,
n_job, n_hack, n_email, n_email_ext, n_device, n_file`. Role and PC are identifiers used for grouping.

**Split (days counted from the first logon day = day 1):** train 1–180, validation 181–210,
test 211–502. `cache/<run>/split_summary.csv` gives sessions and malicious sessions per period, and
`insiders_active_per_period.csv` the number of insiders with malicious sessions in each. These fill
the placeholders in Section V-B.

## 4b. Data audit (before any model)

`python run.py prepare` writes `results/<run>/DATA_AUDIT.md`: event and label matching, session sanity,
malicious sessions and insiders per month and per period, scenario feature profiles, keyword hit rates
(without labels), peer-group sizes and history lengths. The split and keyword lists are frozen after this
step; any change is recorded in `CHANGES.md`.

## 5. Individual branch (`flaitd/individual.py`)  [IV-B]

* Inputs standardised **per user** with the mean/std of that user's training sessions; std floored at
  `0.1 ×` the global std and never below `min_std = 0.1` (model units; CHANGES.md #4) (users with < 2 training
  sessions use global statistics).
* History window `w = 10` previous sessions of the same user (left-padded, masked).
* One-layer LSTM (64 units) → additive temporal attention (32) → context `c_t`; prediction
  `x̂_t = W[c_t; h_{t-1}] + b` (paper Eqs. 2–4). Variant *no attention* uses `h_{t-1}` only.
* One network for all users; MSE loss; Adam, lr 1e-3, batch 256, ≤ 30 epochs, early stopping
  (patience 3) on the validation-period loss (no labels used).
* **Training targets:** training-period sessions; with `clean_train: true` known malicious sessions
  are removed (the only use of labels outside evaluation). Ablation *not cleaned* keeps them.
* **Score:** `s^I_t = mean_j ((z_tj − ẑ_tj)/σ_j)²`, `σ_j` = residual std on validation sessions
  (paper Eq. 5). Residual shares `ρ_tj` are stored as exact per-feature attributions.

## 6. Peer-group branch (`flaitd/group.py`)  [IV-C]

* **Groups per month** from that month's LDAP snapshot (users absent from a snapshot inherit their
  nearest known attributes). Key = role; if fewer than `min_group_size` (10) users are active with that
  role that month, fall back to functional unit + department, then business unit, then everyone.
* **Pool:** for group `g` and month `n`, the sessions of `g`'s members in month `n−1`; if fewer than
  `min_pool` (50), months `n−2`, `n−3` are added; if still too small (or `n` is the first month), the
  month's own sessions are used (counted as *transductive* in the log).
* **Model:** scikit-learn `IsolationForest(n_estimators=100, max_samples=min(256, pool))`, fitted on the
  pool, scoring the group's sessions in month `n`. `s^G = −score_samples = 2^{−E[h(x)]/c(ψ)}` (Eq. 6–7).
  Inputs: the same 14 features, log-transformed, not per-user standardised.
* **Explanations:** TreeSHAP values of the forest; negative contributions push towards "anomalous".

## 7. Normalisation and fuzzy fusion (`flaitd/fuzzy.py`)  [IV-D, IV-E]

* `s̃ = ECDF_val(s)`: the fraction of validation sessions with a score ≤ s (Eq. 8). Ablation *min–max*
  replaces it with min–max scaling on validation scores.
* Input terms Low = trap(0, 0, 0.60, m), Medium = tri(0.60, m, h), High = trap(m, h, 1, 1) with defaults
  m = 0.85, h = 0.97. Output terms VL…VH triangles centred at 0, .25, .5, .75, 1. Nine-rule symmetric
  table (paper Table II). Min for AND, max aggregation, centroid on 201 points (Eqs. 9–11).
* **Breakpoints:** chosen on the validation period from m ∈ {0.80, 0.85, 0.90} × h ∈ {0.95, 0.97, 0.99},
  maximising validation PR-AUC — only if the validation period has ≥ `stacking.min_val_positives` (10)
  malicious sessions; otherwise the defaults are kept. The choice per seed is printed in `RESULTS.md`.
* Unit tests pin the worked examples in the paper: (0.99, 0.50) → 0.50 (Medium), (0.75, 0.75) → 0.37.

## 8. Alerting  [IV-F]

For any continuous score, the threshold `τ_B` is the value exceeded on average by `B = 10` validation
sessions per day (`B × number of validation days` highest validation scores). The same `τ_B` is applied
to the test period. The resulting number of test alerts is reported (column *Alerts*).

## 9. Baselines  [V-C, Table IV]

| Method | Fitted on | Score |
|---|---|---|
| OCSVM (RBF, ν = 0.01) | 20,000 random clean training sessions, globally standardised | −score_samples |
| LOF (k = 20, novelty) | same | −score_samples |
| iForest (pooled) | same, 100 trees, ψ = 256 | −score_samples |
| LSTM-AE | windows of 10 sessions incl. current, per-user standardised, clean training | scaled squared error of the current session |
| I-only / G-only | FLAITD branches alone | percentile score |
| MUEBA (reimpl.) | see below | binary |

### MUEBA reimplementation (`flaitd/mueba.py`)
Taken from the paper: session units; its Table 2 features; window 10; attention-LSTM **classifier**
trained with labels on the first 210 days (our train + validation periods); monthly role groups; a
modified iForest per role group; alert only if both parts flag the session.
MUEBA leaves several details open. Our reading, which the paper must state:

1. Classifier label = label of the last session in the window; class-weighted BCE
   (`pos_weight = negatives/positives`, capped at 1000); 20 epochs, no early stopping.
2. iForest: for each (role, month), fitted and scored on that month's sessions (in-group comparison).
   The undefined "regression error e" is taken as the squared standardised distance of a session to
   the group mean; for each tree, 5 candidate subsamples are drawn and the one containing the most
   sessions outside μ_e ± 3σ_e is used. The "golden point" split is taken as
   `min + 0.618 (max − min)` of a randomly chosen attribute.
3. Thresholds 0.5 for both parts (MUEBA Fig. 4 marks 0.5 as the anomaly boundary).
4. The two parts are also reported alone (supplementary rows), which lets readers check Proposition 1
   on MUEBA itself.

## 10. Fusion comparison  [VI-B, Table V]

All rules use the same two FLAITD branches and percentile scores. Mean, Maximum, Product and FLAITD
are thresholded with `τ_B`. **AND/OR** use one common percentile `q` for both branches, chosen by
bisection so that they raise `B` alerts per day on validation (budget-matched; single operating point,
so no PR-AUC). **Stacking**: logistic regression on (s̃^I, s̃^G, s̃^I·s̃^G) with balanced class weights,
fitted on validation labels; if validation has fewer than 10 malicious sessions it is fitted by grouped
5-fold cross-validation on the test users instead — an optimistic reference, flagged in `RESULTS.md`.

## 11. Ablations  [VI-C, Table VI; VI-E, Table VIII]

`no_attention`, `static_roles` (first-month attributes for the whole period), `no_fallback` (strict role
groups), `eif` (Extended Isolation Forest, hyperplane splits, `flaitd/itree.py`), `minmax`, `no_clean`,
`no_keywords` (11 features, both branches retrained; reported in Table VIII). Each ablation reuses the
full model's fuzzy breakpoints, so only the named component changes.

## 12. Metrics  [V-D]

On test sessions: **PR-AUC** (average precision; headline), ROC-AUC; at `τ_B`: precision, recall, F1,
number of alerts. **User level:** an insider counts as *detected* if at least one of the malicious
sessions they own is alerted; *benign users alerted* counts non-insiders with at least one alert on a
benign session. **Per scenario:** detected / active insiders for scenarios 1–3 (Table VII).
Accuracy is not reported: `summary.json → stats.all_benign_accuracy_test` gives the accuracy of
labelling everything benign, for the sentence in Section V-D.

## 13. Statistics

Mean ± std over seeds 0–4. For seed 0, a paired bootstrap over users (1,000 resamples; every
session of a resampled user carries its weight) gives the 95% CI of PR-AUC(FLAITD) − PR-AUC(method).
`RESULTS.md` also lists insiders found by only one branch — exactly the cases AND fusion loses.

## 14. Explanations  [VI-F]

On seed 0, for true-positive test alerts: fired rules with strengths, the three largest residual
shares, the three largest TreeSHAP contributions, raw feature values and attention weights
(`results/<run>/explanations/case_studies.json`; up to 20 cases spread over scenarios).
**Deletion test:** for up to 500 true-positive alerts, the three features with the largest combined
attribution (residual share + normalised negative SHAP) are replaced by the user's median over clean
training sessions; the session is rescored through both branches, the same ECDFs and the fuzzy layer.
Compared with replacing three random features (10 draws). Reported: mean risk drop (top-3 vs random)
and the share of alerts that fall below `τ_B`.

## 15. Where each paper placeholder comes from

| Paper location | Output |
|---|---|
| Abstract, VI-A numbers; Table IV | `RESULTS.md` Table IV; bootstrap table |
| Table V and VI-B text | Table V; "Stacking" note |
| Table VI | Table VI |
| Table VII; one-branch insiders sentence | Table VII; bootstrap section last line |
| Table VIII | Table VIII |
| V-A session counts; V-B split counts | `cache/full/sessions_meta.json`, `split_summary.csv`, `insiders_active_per_period.csv` |
| V-D all-benign accuracy | `summary.json → stats.all_benign_accuracy_test` |
| Fuzzy breakpoints (IV-E) | "Fuzzy breakpoints" section |
| VI-F case study and deletion test | `explanations/case_studies.json`, `deletion_test.json` |
| VI-G run time | "Run time" section (+ state your CPU/GPU and RAM) |
| Fig. 4 (optional PR curves) | `fig_pr_curves_seed0.png` |

## 16. Expected run time

Measured on synthetic data and extrapolated: full r4.2 on a 4–8 core laptop CPU ≈ 20–40 min for
ingest + sessions (http.csv dominates) and ≈ 30–40 min per seed for all models and ablations, so about
3–4 hours for five seeds. A CUDA GPU shortens the LSTM parts. Every stage is cached; a rerun skips
finished work, and `--force` recomputes data stages.
