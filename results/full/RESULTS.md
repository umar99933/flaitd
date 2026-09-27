# FLAITD results — run `full`

Seeds: [0, 1, 2, 3, 4]. Values are mean ± std over seeds. Budget B = 10 alerts/day.

## Table IV — comparison with baselines (test period)

| Method | PR-AUC | ROC-AUC | P@B | R@B | F1@B | Insiders | Benign users alerted | Alerts |
|---|---|---|---|---|---|---|---|---|
| OCSVM | 0.005 ± 0.000 | 0.503 ± 0.012 | 0.012 ± 0.001 | 0.045 ± 0.006 | 0.019 ± 0.002 | 24.8/61 | 347.6 ± 10.5 | 3217 ± 67 |
| LOF | 0.009 ± 0.000 | 0.725 ± 0.008 | 0.015 ± 0.001 | 0.045 ± 0.003 | 0.023 ± 0.002 | 27.0/61 | 427.0 ± 30.0 | 2509 ± 138 |
| iForest (pooled) | 0.016 ± 0.001 | 0.870 ± 0.009 | 0.010 ± 0.002 | 0.029 ± 0.004 | 0.015 ± 0.003 | 9.8/61 | 92.0 ± 15.8 | 2450 ± 197 |
| LSTM-AE | 0.040 ± 0.001 | 0.875 ± 0.007 | 0.028 ± 0.001 | 0.342 ± 0.029 | 0.051 ± 0.003 | 50.4/61 | 364.0 ± 15.6 | 10234 ± 538 |
| I-only (ours) | 0.042 ± 0.000 | 0.867 ± 0.001 | 0.023 ± 0.000 | 0.163 ± 0.001 | 0.040 ± 0.000 | 47.6/61 | 511.0 ± 4.1 | 5948 ± 62 |
| G-only (ours) | 0.018 ± 0.001 | 0.863 ± 0.005 | 0.027 ± 0.001 | 0.074 ± 0.003 | 0.040 ± 0.002 | 32.0/61 | 158.4 ± 7.3 | 2270 ± 56 |
| MUEBA (reimpl.) | — | — | 0.141 ± 0.011 | 0.517 ± 0.041 | 0.221 ± 0.014 | 47.6/61 | 118.2 ± 19.2 | 3053 ± 317 |
| FLAITD | 0.031 ± 0.002 | 0.890 ± 0.003 | 0.045 ± 0.004 | 0.144 ± 0.010 | 0.068 ± 0.005 | 46.0/61 | 251.4 ± 4.3 | 2650 ± 55 |
| MUEBA LSTM part | 0.280 ± 0.021 | 0.891 ± 0.028 | 0.103 ± 0.021 | 0.566 ± 0.046 | 0.173 ± 0.030 | 47.8/61 | 128.0 ± 18.2 | 4787 ± 1151 |
| MUEBA iForest part | 0.020 ± 0.000 | 0.875 ± 0.001 | 0.014 ± 0.000 | 0.888 ± 0.007 | 0.027 ± 0.000 | 61.0/61 | 884.2 ± 1.2 | 54250 ± 256 |

## Table V — fusion rules

| Fusion | PR-AUC | P@B | R@B | Insiders | Alerts |
|---|---|---|---|---|---|
| AND | — | 0.048 ± 0.004 | 0.154 ± 0.009 | 46.2/61 | 2653 ± 65 |
| OR | — | 0.018 ± 0.001 | 0.096 ± 0.002 | 40.6/61 | 4439 ± 113 |
| Mean | 0.034 ± 0.002 | 0.046 ± 0.003 | 0.148 ± 0.010 | 46.0/61 | 2639 ± 18 |
| Maximum | 0.029 ± 0.001 | 0.018 ± 0.001 | 0.096 ± 0.002 | 40.6/61 | 4456 ± 107 |
| Product | 0.034 ± 0.002 | 0.046 ± 0.003 | 0.148 ± 0.009 | 45.8/61 | 2643 ± 16 |
| Stacking (LR) | 0.030 ± 0.002 | 0.041 ± 0.003 | 0.125 ± 0.009 | 44.2/61 | 2541 ± 78 |
| FLAITD | 0.031 ± 0.002 | 0.045 ± 0.004 | 0.144 ± 0.010 | 46.0/61 | 2650 ± 55 |

## Table VI — ablation

| Variant | PR-AUC | R@B |
|---|---|---|
| Full FLAITD | 0.031 ± 0.002 | 0.144 ± 0.010 |
| Without attention (plain LSTM) | 0.031 ± 0.002 | 0.145 ± 0.010 |
| Static roles (first month only) | 0.031 ± 0.002 | 0.144 ± 0.010 |
| No small-group fallback | 0.031 ± 0.002 | 0.145 ± 0.010 |
| Extended Isolation Forest | 0.020 ± 0.000 | 0.084 ± 0.003 |
| Min-max instead of ECDF | 0.012 ± 0.001 | 0.076 ± 0.003 |
| Training data not cleaned | 0.030 ± 0.001 | 0.140 ± 0.009 |

## Table VII — insiders detected per scenario

| Scenario | Active | I-only | G-only | AND | FLAITD |
|---|---|---|---|---|---|
| 1 | 25.0 ± 0.0 | 25.0 ± 0.0 | 21.8 ± 0.4 | 24.2 ± 0.7 | 24.4 ± 0.5 |
| 2 | 30.0 ± 0.0 | 16.6 ± 0.5 | 7.2 ± 1.0 | 16.0 ± 0.6 | 15.6 ± 0.5 |
| 3 | 6.0 ± 0.0 | 6.0 ± 0.0 | 3.0 ± 0.6 | 6.0 ± 0.0 | 6.0 ± 0.0 |

## Table VIII — without keyword features

| Method | PR-AUC all 14 | PR-AUC without K | R@B all 14 | R@B without K |
|---|---|---|---|---|
| I-only | 0.042 ± 0.000 | 0.035 ± 0.000 | 0.163 ± 0.001 | 0.099 ± 0.001 |
| G-only | 0.018 ± 0.001 | 0.014 ± 0.000 | 0.074 ± 0.003 | 0.057 ± 0.002 |
| FLAITD | 0.031 ± 0.002 | 0.021 ± 0.001 | 0.144 ± 0.010 | 0.085 ± 0.002 |

## Fuzzy breakpoints

- seed 0: {'medium_peak': 0.8, 'high_full': 0.99} (tuned on validation (AP=0.069))
- seed 1: {'medium_peak': 0.8, 'high_full': 0.99} (tuned on validation (AP=0.083))
- seed 2: {'medium_peak': 0.8, 'high_full': 0.99} (tuned on validation (AP=0.072))
- seed 3: {'medium_peak': 0.8, 'high_full': 0.99} (tuned on validation (AP=0.070))
- seed 4: {'medium_peak': 0.8, 'high_full': 0.99} (tuned on validation (AP=0.068))

## Notes

- Stacking: fitted on validation labels

## Seed 0: paired bootstrap over users, PR-AUC(FLAITD) − PR-AUC(method)

| Method | mean diff | 95% CI | P(diff ≤ 0) |
|---|---|---|---|
| I-only | -0.009 | [-0.025, 0.005] | 0.875 |
| G-only | 0.014 | [0.007, 0.022] | 0.000 |
| Mean | -0.004 | [-0.011, -0.000] | 0.975 |
| Maximum | 0.002 | [-0.011, 0.013] | 0.362 |
| Product | -0.004 | [-0.011, -0.000] | 0.979 |
| OCSVM | 0.030 | [0.019, 0.042] | 0.000 |
| LOF | 0.025 | [0.015, 0.037] | 0.000 |
| iForest (pooled) | 0.017 | [0.007, 0.029] | 0.001 |
| LSTM-AE | -0.008 | [-0.023, 0.005] | 0.878 |

Insiders detected by I-only but not G-only: 17; by G-only but not I-only: 0; by both: 31 (these one-branch cases are what AND fusion loses).

## Dataset statistics

```
{
 "ingest_meta.json": {
  "n_mal_ids": 7323,
  "files": {
   "logon": {
    "rows_read": 854859,
    "rows_kept": 854859,
    "malicious": 198,
    "bad_dates": 0,
    "seconds": 4.5
   },
   "device": {
    "rows_read": 405380,
    "rows_kept": 405380,
    "malicious": 2785,
    "bad_dates": 0,
    "seconds": 2.3
   },
   "file": {
    "rows_read": 445581,
    "rows_kept": 445581,
    "malicious": 10,
    "bad_dates": 0,
    "seconds": 5.2
   },
   "email": {
    "rows_read": 2629979,
    "rows_kept": 2629979,
    "malicious": 470,
    "bad_dates": 0,
    "seconds": 36.8
   },
   "http": {
    "rows_read": 28434423,
    "rows_kept": 28434423,
    "malicious": 3860,
    "bad_dates": 0,
    "seconds": 525.1
   }
  },
  "malicious_events_matched": 7323
 },
 "sessions_meta.json": {
  "device": {
   "events": 405380,
   "assigned": 405354,
   "unassigned": 26,
   "malicious": 2785,
   "malicious_assigned": 2785
  },
  "file": {
   "events": 445581,
   "assigned": 445550,
   "unassigned": 31,
   "malicious": 10,
   "malicious_assigned": 10
  },
  "email": {
   "events": 2629979,
   "assigned": 2629825,
   "unassigned": 154,
   "malicious": 470,
   "malicious_assigned": 470
  },
  "http": {
   "events": 28434423,
   "assigned": 28432718,
   "unassigned": 1705,
   "malicious": 3860,
   "malicious_assigned": 3860
  },
  "sessions": 384251,
  "unlocks_merged": 86340,
  "orphan_sessions": 0,
  "capped": 0,
  "malicious_sessions": 1030,
  "logon_rows": 854859
 },
 "per_period": {
  "sessions": {
   "test": 210551,
   "train": 149638,
   "val": 24062
  },
  "malicious": {
   "test": 829,
   "train": 45,
   "val": 156
  },
  "days": {
   "test": 291,
   "train": 180,
   "val": 30
  },
  "insiders_active": {
   "test": 61,
   "train": 6,
   "val": 17
  }
 },
 "insiders_per_scenario": {
  "1": 30,
  "2": 30,
  "3": 10
 },
 "sessions_total": 384251,
 "malicious_total": 1030,
 "base_rate_test": 0.003937288352940617,
 "all_benign_accuracy_test": 0.9960627116470594
}
```

## Run time (mean over seeds, seconds)

```
{
 "individual_train_s": 31.4,
 "group_s": 64.3,
 "fuzzy_all_sessions_s": 3.5,
 "OCSVM_s": 5.9,
 "LOF_s": 43.9,
 "iForest (pooled)_s": 1.4,
 "seed_total_s": 1511.2
}
```

## Deletion test (seed 0)

```
{
  "n_true_positive_alerts": 121,
  "n_tested": 121,
  "mean_drop_top3": 0.26627379253011857,
  "mean_drop_random3": 0.04024459372952688,
  "share_below_tau_after_top3": 0.9917355371900827,
  "tau": 0.8388749974877285
}
```

Case studies: `F:/flaitd/results/full/explanations/case_studies.json`
