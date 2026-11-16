# Static Malware Detection on PE Files — Forensics, Model Evaluation, TreeSHAP & SOC Cost Optimisation

**Module M115 – AI & Intelligent Systems · Lab 2 · Master Sécurité des Systèmes Intelligents et Cyberdéfense (ENSIASD Taroudant, Ibn Zohr University) · 2026–2027**

A complete, executed solution of Lab 2 and its homework: an end-to-end, leakage-safe machine-learning study of **static Windows PE-file malware detection** for a fictional payment company (*AtlasPay Services*), ending with a defensible recommendation to the CISO.

> **Scope note.** AtlasPay, the incident, the operating figures and all costs are fictional teaching assumptions. The data are a deterministic **EMBER-inspired synthetic dataset** (6,000 PE records, seed 42). They are **not** real telemetry and **not** the real EMBER benchmark, so nothing here is evidence of production detection performance.

## Contents

```
.
├── M115_Lab2_Static_Malware_Detection.ipynb   # executed notebook: code, outputs, answers to Parts A–F, CISO memo
├── figures/                                    # all plots produced by the notebook
├── results/                                    # CSV exports (CV table, thresholds, latency, capacity what-if)
├── requirements.txt
└── README.md
```

## What the notebook does

| Phase | Content |
|---|---|
| 1. Forensic data audit | class balance, missing values, duplicates, parser sentinel (`99999.0`), two leakage/governance traps, feature relationships, archetype profiling |
| 2. Leakage-safe CV | stratified 80/20 development/**lockbox** split; `Pipeline`s (median imputation, `RobustScaler` for LR only); 5-fold stratified CV; latency measurement |
| 3. Model benchmark | Logistic Regression, deep Decision Tree, Random Forest, LightGBM, Stacking (LR + RF + LightGBM) |
| 4. Error forensics & TreeSHAP | a *verified* model disagreement on the lockbox, global (beeswarm) and local (waterfall) SHAP |
| 5. SOC cost & thresholds | cost-minimising thresholds from **out-of-fold** development predictions, frozen, evaluated once on the lockbox; triage (FP = $25) vs blocking (FP = $2,000) |
| Memo | executive recommendation for the CISO |

### Data traps handled

* `VT_PostScan_Detections` — recorded *after* scanning: **target leakage** (CV F1 jumps from 0.924 to 0.999 when included) → excluded.
* `SHA256_File_ID` — pure identifier → excluded (kept only to identify rows in the forensics section).
* `Virtual_to_Raw_Size_Ratio == 99999.0` — 59 parser sentinels (0.98 %) → turned into `NaN` and median-imputed inside each fold.
* Missing values (`Import_Count` 3.8 %, `Resource_Entropy` 4.8 %) → imputation **inside** the pipeline, never on the full data.

## Key results (this run, seed 42)

**5-fold stratified CV on the development set (4,800 files)**

| Model | Train F1 | Val F1 | Gap | Val PR-AUC |
|---|---|---|---|---|
| Logistic Regression | 0.923 | 0.924 | −0.001 | 0.908 |
| Decision Tree (deep) | 1.000 | 0.830 | **0.170** | 0.733 |
| Random Forest | 1.000 | 0.924 | 0.076 | 0.905 |
| LightGBM | 0.956 | 0.923 | 0.034 | 0.909 |
| Stacking | 0.929 | 0.925 | 0.004 | 0.909 |

The single deep tree clearly overfits; the other four are **statistically indistinguishable** (PR-AUC differences ≈ 0.003 vs fold std ≈ 0.02). The linear baseline is already competitive.

**Cost-optimal thresholds** (selected on out-of-fold dev predictions, frozen, evaluated once on the 1,200-file lockbox)

| Scenario | Model | τ | TP | FP | FN | Precision | Recall | Cost |
|---|---|---|---|---|---|---|---|---|
| Triage (FP $25, FN $500) | Logistic Regression | 0.28 | 288 | 10 | 34 | 0.966 | 0.894 | $17,250 |
| Blocking (FP $2,000, FN $500) | Logistic Regression | 0.50 | 286 | 8 | 36 | 0.973 | 0.888 | $34,000 |

Theoretical Bayes thresholds for calibrated probabilities are `C_FP/(C_FP+C_FN)` = 0.048 (triage) and 0.80 (blocking); the empirical ones differ because of calibration, a flat cost curve, and a ≈ 4 % label-noise floor (≈ 34 FN at any sensible threshold). Full tables for all four shortlisted models are in `results/threshold_results.csv`.

**Error forensics.** At threshold 0.5, Logistic Regression and LightGBM disagree on only 3 of 1,200 lockbox files. The verified malware case `sha256_05115_pe` has LR p = 0.426 (missed) vs LightGBM p = 0.970 (caught); TreeSHAP attributes it mainly to `Virtual_to_Raw_Size_Ratio` (+3.49), `Export_Count` (+1.97) and `Num_Sections` (+0.47). SHAP explains the *model*; it is not causal proof that the file is malicious.

![SHAP waterfall for the verified case](figures/04_shap_waterfall_case.png)
![Cost curves and calibration](figures/06_cost_curves_calibration.png)

## Conclusion (CISO recommendation)

* Start in **shadow mode**, then **analyst-assisted triage** on a capped queue; **no autonomous blocking**.
* First scorer: **Logistic Regression** (lowest out-of-fold cost, no overfitting gap, ≈ 1 ms per 1,000 files, auditable); run **LightGBM** as challenger and SHAP explainer.
* The 120 alerts/day target is **not demonstrated**: the lockbox has 26.8 % malware, and even the false alerts alone (FPR 1.1 % × 12,000 files ≈ 137/day) exceed the target. A reliable forecast needs representative telemetry, true prevalence and re-calibration.
* Gates before any blocking pilot: temporal evaluation on real data, calibration, capacity test, sandbox corroboration, rollback/override, drift monitoring.

## Reproduce

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
jupyter lab M115_Lab2_Static_Malware_Detection.ipynb    # Kernel > Restart & Run All (≈ 2 min on 2 CPU cores)
```

Notes: the random seed is fixed (`SEED = 42`); metrics are reproducible, **timings are not** (they depend on hardware). If LightGBM is not installed the notebook falls back to `HistGradientBoostingClassifier` and labels it accordingly. Tested with Python 3.13, scikit-learn 1.9, LightGBM 4.7, SHAP 0.54.

## Methodological rules followed

1. No learned preprocessing outside the cross-validation pipeline.
2. The lockbox test set is never used for model selection or threshold tuning; thresholds are frozen before a single evaluation.
3. Every number in the written answers comes from the executed outputs; observation, interpretation, hypothesis and recommendation are kept distinct.

## Author

Med Amine — Master Sécurité des Systèmes Intelligents et Cyberdéfense · Lab 2 of module M115 (Prof. S. EL-ATEIF).
