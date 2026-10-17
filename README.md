# Financial SQL Injection WAF

A Web Application Firewall prototype that detects and blocks SQL injection
attacks against a simulated banking ledger. It combines TF-IDF text features
with structural features and classifies queries using a Random Forest model.

## Features

- Real-time query inspection through a Streamlit security console
- Automatic blocking (403) and quarantine of malicious queries
- Forensic vault for reviewing intercepted attacks
- Built-in stress benchmark for throughput and latency

## Tech Stack

Python, scikit-learn, Streamlit, pandas, NumPy, pytest

## Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the dashboard

```bash
streamlit run app.py
```

### 3. Run the tests

```bash
pytest test_strategy.py
```

## Dataset

The dataset is not included in this repository. To regenerate the
partitioned data, place `financial_sqli_master_10k.csv` in a `data/` folder
at the project root, then run:

```bash
python split_data.py
```

This creates `data/raw/normal/` and `data/raw/malicious/`.

## Project Structure

| File | Description |
|---|---|
| `app.py` | Detection pipeline and Streamlit dashboard |
| `test_strategy.py` | Unit and UI tests |
| `split_data.py` | Splits the master dataset into normal and malicious sets |
| `generateallqueries.py` | Generates the SQL query dataset |
| `MajorProject.ipynb` | Model training and evaluation |
| `training_logs.json` | Results from comparing eight models |

## Results

Add your key metrics here (accuracy, precision, recall, latency).

![Dashboard](<Screenshot 2026-10-17 183846.png>)