# FLAITD — code for the paper

Fuzzy fusion of an individual-history model (attention-LSTM) and a peer-group model (Isolation Forest)
for insider threat detection on CERT r4.2, with every baseline, ablation and table in the paper.
The full protocol is in **METHODOLOGY.md**; read it before running.

## 1. Install (Windows, macOS or Linux, Python 3.10+)

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q tests                 # 7 tests, a few seconds
```
A CUDA GPU is used automatically if PyTorch sees one; CPU works.

## 2. Get the data

Download `r4.2.tar.bz2` and `answers.tar.bz2` from the CERT Insider Threat Test Dataset on
Carnegie Mellon's KiltHub (doi:10.1184/R1/12841247). Extract so that you have:

```
data/r4.2/{logon,device,file,email,http}.csv   data/r4.2/LDAP/*.csv
data/answers/insiders.csv                      data/answers/r4.2-1/ r4.2-2/ r4.2-3/
```
(On Windows, 7-Zip extracts .tar.bz2. The data needs about 17 GB of disk once extracted.)
Other locations work too: set `data_dir` and `answers_dir` in the config.

## 3. Run

```bash
python run.py check                                   # pre-flight: files, headers, dates, answers
python run.py prepare                                 # ingest, sessions, features + DATA_AUDIT.md (read it!)
python run.py --config config/chunk.yaml all          # debug run: all insiders + 200 benign users, 2 seeds
python run.py all                                     # full run (config/default.yaml), 5 seeds -> paper numbers
```
Stages can be run one at a time: `ingest`, `sessions`, `features`, `audit`, `experiment`, `explain`, `report`.
Each stage caches its output, so an interrupted run resumes; `--force` recomputes the data stages and
`--seeds 0 1` limits the seeds.

Smoke test without CERT (synthetic data in CERT format, results meaningless):
```bash
python tools/make_synthetic_cert.py --out data/synthetic
python run.py --config config/synthetic.yaml all
```

## 4. Outputs

`results/<run>/RESULTS.md` contains Tables IV–VIII (mean ± std over seeds), fuzzy breakpoints, the
bootstrap CIs, insiders found by only one branch, dataset statistics, run times and the deletion test.
CSV copies of each table, `summary.json`, `fig_pr_curves_seed0.png` and
`explanations/case_studies.json` sit next to it. METHODOLOGY.md §15 maps each output to its place in the paper.

This repository publishes the final tables of the full CERT r4.2 run in `results/full/RESULTS.md` and the
supplementary analyses in `results/full/extra/CHECKS.md` (scripts in `tools/`). Every deviation from the
protocol and every analysis added after the main run is logged in `CHANGES.md`. Per-seed score files are
not included; `python run.py all` regenerates them. The CERT data is not redistributed here.

## 5. Layout

```
run.py                  command line
config/                 default.yaml (full), chunk.yaml, synthetic.yaml
flaitd/ingest.py        stream raw CSVs -> compact parquet, label events from the answer key
flaitd/sessions.py      logon/logoff pairing, orphan repair, event assignment
flaitd/features.py      14 session features, MUEBA features, day split
flaitd/individual.py    attention-LSTM predictor (individual branch)
flaitd/group.py         monthly peer groups + Isolation Forest (peer branch)
flaitd/fuzzy.py         Mamdani fusion, ECDF / min-max normalisation
flaitd/baselines.py     OCSVM, LOF, pooled iForest, LSTM autoencoder
flaitd/mueba.py         MUEBA reimplementation
flaitd/itree.py         Extended iForest and MUEBA's modified iForest (NumPy)
flaitd/pipeline.py      all fusion rules, baselines and ablations per seed
flaitd/metrics.py       PR-AUC, budget metrics, user-level metrics, bootstrap
flaitd/explain.py       case studies, TreeSHAP, deletion test
flaitd/report.py        tables, CIs, figure
tools/make_synthetic_cert.py   synthetic data in CERT format for testing
tools/fusion_checks.py, mueba_no_keywords.py, extra_checks2.py, union_budget.py, posthoc_after_freeze.py   supplementary analyses (CHECKS.md)
```

## 6. License and citation

MIT License (see `LICENSE`). If you use this code, please cite it using `CITATION.cff`.
