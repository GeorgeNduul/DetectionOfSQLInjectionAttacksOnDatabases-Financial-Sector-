import streamlit as st
import time
import re
import uuid
import json
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

# Set page configuration
st.set_page_config(
    page_title="Security Console",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================================
# 1. CORE PIPELINE & MODEL SETUP (CACHED)
# =========================================================================
def clean_sql_query(query):
    if not isinstance(query, str):
        return ""
    query = query.lower()
    query = re.sub(re.compile(r"/\*.*?\*/", re.DOTALL), "", query)
    query = re.sub(r"--.*$", "", query)
    query = re.sub(r"\b\d+\b", " NUM ", query)
    query = re.sub(re.compile(r"([=\(\)\<\>\!\,;'\"\.])"), r" \1 ", query)
    query = re.sub(r"\s+", " ", query).strip()
    return query

def extract_single_structural_features(cleaned_query):
    query_len = len(cleaned_query)
    special_chars = sum(1 for c in cleaned_query if c in ["'", '"', ';', '-', '*', '#', '='])
    has_tautology = int(bool(re.search(r"\b(or|and)\b\s+\S+\s*=\s*\S+", cleaned_query, re.IGNORECASE)))
    union_count = cleaned_query.count('union')
    select_count = cleaned_query.count('select')
    has_blind = int(bool('sleep' in cleaned_query or 'waitfor' in cleaned_query or 'benchmark' in cleaned_query))
    has_comments = int(bool('--' in cleaned_query or '/*' in cleaned_query or '#' in cleaned_query))
    return np.array([query_len, special_chars, has_tautology, union_count, select_count, has_blind, has_comments]).reshape(1, -1)

@st.cache_resource
def initialize_production_environment():
    # Expanded training footprint for cleaner conceptual boundaries
    mock_train_data = [
        # Safe Traffic (0)
        "SELECT * FROM accounts WHERE customer_id = 101", 
        "SELECT balance FROM ledgers WHERE account_num = 4556",
        "SELECT owner FROM accounts WHERE account_num = 'ACC-1102'",
        "SELECT status FROM ledgers WHERE customer_id = 'ACC-4091'",
        # Malicious Traffic (1)
        "SELECT * FROM card_registry WHERE pin = '123' OR 1=1 --",
        "SELECT wire_history FROM Swift_logs WHERE id = 1 UNION SELECT password FROM admin",
        "SELECT * FROM accounts WHERE customer_id = '' OR '1'='1'",
        "SELECT balance FROM ledgers WHERE account_num = 4556; DROP TABLE ledgers; --"
    ]
    mock_labels = [0, 0, 0, 0, 1, 1, 1, 1]
    cleaned_mock = [clean_sql_query(q) for q in mock_train_data]

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1000)
    X_tfidf_mock = vectorizer.fit_transform(cleaned_mock).toarray()
    struct_features_list = [extract_single_structural_features(q).flatten() for q in cleaned_mock]
    scaler = StandardScaler()
    X_struct_mock = scaler.fit_transform(struct_features_list)
    X_combined_mock = np.hstack((X_tfidf_mock, X_struct_mock))
    
    model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
    model.fit(X_combined_mock, mock_labels)
    return model, vectorizer, scaler

production_model, vectorizer, scaler = initialize_production_environment()

# =========================================================================
# 2. STATE MANAGEMENT FOR SESSION RETENTION
# =========================================================================
if "quarantine_vault" not in st.session_state:
    st.session_state.quarantine_vault = {}
if "traffic_logs" not in st.session_state:
    st.session_state.traffic_logs = []

# =========================================================================
# 3. CORE COMPONENTS
# =========================================================================
class FinancialDatabaseLedger:
    def __init__(self):
        # Expanded to match all possible test queries dynamically
        self.accounts = {
            "ACC-4091": {"Owner": "Corporate Payroll Pool", "Balance": 8450000.00, "Status": "Active"},
            "ACC-1102": {"Owner": "Retail High-Net-Worth Account", "Balance": 125000.50, "Status": "Active"},
            "101": {"Owner": "Alice Smith", "Balance": 5400.00, "Status": "Active"},
            "4556": {"Owner": "Bob Jones", "Balance": 12500.00, "Status": "Active"}
        }
    def query_ledger(self, account_id):
        return {"status": "200 OK", "payload": self.accounts.get(account_id, f"Record '{account_id}' Not Found")}

class ForensicQuarantineSystem:
    def isolate_threat(self, threat_metadata):
        tx_id = threat_metadata["transaction_id"]
        st.session_state.quarantine_vault[tx_id] = {
            "Timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "Payload": threat_metadata["raw_query"],
            "Risk Tier": "CRITICAL_HIGH",
            "String Length": threat_metadata["metadata"]["string_length"],
            "Special Chars": threat_metadata["metadata"]["special_characters_detected"],
            "Tautology Flags": threat_metadata["metadata"]["structural_tautology_found"],
            "Union Count": threat_metadata["metadata"]["union_keywords_count"]
        }

class AutomatedIncidentPreventionGateway:
    def __init__(self, model, vectorizer, scaler, database, quarantine_sys):
        self.model = model
        self.vectorizer = vectorizer
        self.scaler = scaler
        self.db = database
        self.quarantine = quarantine_sys

    def process_transaction(self, raw_query, quiet=False):
        tx_id = f"FIN-TX-{str(uuid.uuid4())[:8].upper()}"
        start_perf = time.perf_counter()
        
        cleaned = clean_sql_query(raw_query)
        tfidf_feat = self.vectorizer.transform([cleaned]).toarray()
        struct_feat = extract_single_structural_features(cleaned)
        struct_feat_scaled = self.scaler.transform(struct_feat)
        combined_features = np.hstack((tfidf_feat, struct_feat_scaled))
        
        prediction = self.model.predict(combined_features)[0]
        processing_latency_ms = (time.perf_counter() - start_perf) * 1000
        
        metadata_payload = {
            "transaction_id": tx_id,
            "raw_query": raw_query,
            "processing_latency_ms": round(processing_latency_ms, 3),
            "metadata": {
                "string_length": len(raw_query),
                "special_characters_detected": int(struct_feat[0][1]),
                "structural_tautology_found": bool(struct_feat[0][2]),
                "union_keywords_count": int(struct_feat[0][3])
            }
        }
        
        log_entry = {
            "Transaction ID": tx_id,
            "Timestamp": time.strftime('%H:%M:%S'),
            "Raw Payload": raw_query,
            "Latency (ms)": round(processing_latency_ms, 3),
            "Status": "BLOCKED 🚫" if prediction == 1 else "ALLOWED 🟢"
        }
        st.session_state.traffic_logs.insert(0, log_entry)
        
        if prediction == 1:
            self.quarantine.isolate_threat(metadata_payload)
            if not quiet:
                st.toast(f"🚨 Admin Alert: Attack Intercepted on {tx_id}!", icon="❌")
            return {"status": 403, "tx_id": tx_id, "metadata": metadata_payload}
        else:
            # IMPROVEMENT: Extract the target database identifier dynamically from query syntax
            id_match = re.search(r"=\s*['\"]?([A-Za-z0-9_-]+)", raw_query)
            extracted_id = id_match.group(1) if id_match else "UNKNOWN"
            
            db_res = self.db.query_ledger(extracted_id)
            return {"status": 200, "tx_id": tx_id, "db_response": db_res}

# Instantiate Assets
ledger_db = FinancialDatabaseLedger()
quarantine_sys = ForensicQuarantineSystem()
security_gateway = AutomatedIncidentPreventionGateway(
    model=production_model,
    vectorizer=vectorizer,
    scaler=scaler,
    database=ledger_db,
    quarantine_sys=quarantine_sys
)

# =========================================================================
# 4. STREAMLIT GRAPHICAL USER INTERFACE
# =========================================================================
st.title("🛡️ Financial Core Intelligent WAF Security Console")
st.markdown("Automated Detection + Prevention Dashboard Engine")
st.write("---")

tab1, tab2, tab3 = st.tabs(["⚡ Live Gateway Inspection", "🗃️ Forensic Quarantine Vault", "📊 Stress Engine Benchmark"])

# --- TAB 1: LIVE INSPECTION PIPELINE ---
with tab1:
    st.header("Real-Time Payload Verification Pipeline")
    st.write("Simulate direct corporate database interactions and monitor active mitigation responses.")
    
    input_query = st.text_area("Inbound Transaction SQL Query:", value="SELECT balance FROM ledgers WHERE account_num = 4556")
    
    if st.button("Transmit Query via Gateway"):
        response = security_gateway.process_transaction(input_query)
        
        if response["status"] == 403:
            st.error(f"🛑 [403 Forbidden] Transaction {response['tx_id']} Terminated: Anti-Fraud Guardrails Triggered.")
            
            with st.expander("🚨 Live Admin Infrastructure Breach Alert Payload", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.metric(label="Target Area", value="Financial Core Ledger Space")
                    st.metric(label="Action Taken", value="Dropped & Quarantined", delta="- Risk Blocked")
                with col2:
                    st.markdown(f"**Transaction ID:** `{response['tx_id']}`")
                    st.markdown("**Signature Match:** Tautology/Union structural signature matched via RF Classifier Model.")
                    st.json(response["metadata"]["metadata"])
        else:
            st.success(f"🟢 [200 OK] Access Granted. Transaction {response['tx_id']} passed risk verification points.")
            st.subheader("Database Core Ledger Payload Response:")
            st.json(response["db_response"])

    st.write("---")
    st.subheader("Central Gateway Pipeline Traffic Monitoring Logs")
    if st.session_state.traffic_logs:
        st.dataframe(pd.DataFrame(st.session_state.traffic_logs), use_container_width=True)
    else:
        st.info("No query records currently logged in this routing session.")

# --- TAB 2: FORENSIC QUARANTINE SYSTEM ---
with tab2:
    st.header("⚠️ Isolated Threat Quarantine Repository")
    st.write("Malicious queries isolated and structured into compliance vault schemas for forensic analysis.")
    
    if st.session_state.quarantine_vault:
        if st.button("Clear Forensic Repository"):
            st.session_state.quarantine_vault = {}
            st.rerun()
            
        q_df = pd.DataFrame.from_dict(st.session_state.quarantine_vault, orient='index')
        st.dataframe(q_df, use_container_width=True)
        
        st.subheader("Raw Storage Inspection Schema")
        st.json(st.session_state.quarantine_vault)
    else:
        st.info("Excellent. Quarantine environment remains completely empty. No active compromises detected.")

# --- TAB 3: BENCHMARK STRESS PIPELINE ENGINE ---
with tab3:
    st.header("Throughput & Latency Metric Engine")
    st.write("Evaluate system capabilities by pushing structural transactions through the machine learning model validation steps.")
    
    # Updated to perfectly yield a realistic 50/50 allow/block split based on the new model training footprint
    stress_samples = [
        "SELECT * FROM accounts WHERE customer_id = 101",
        "SELECT owner FROM accounts WHERE account_num = 'ACC-1102'",
        "SELECT * FROM credit_cards WHERE card_no = '1234' OR 1=1 --",
        "SELECT routing_number FROM banks WHERE id = 5 UNION SELECT password FROM admin --"
    ]
    
    if st.button("Execute 1,000 Query Stress Run"):
        with st.spinner("Processing continuous data streams..."):
            start_time = time.perf_counter()
            
            for _ in range(250):
                for q in stress_samples:
                    security_gateway.process_transaction(q, quiet=True)
                    
            total_duration = time.perf_counter() - start_time
            tps = 1000 / total_duration
            avg_latency = (total_duration / 1000) * 1000
            
            m1, m2, m3 = st.columns(3)
            m1.metric("Processing Time", f"{total_duration:.3f} Sec")
            m2.metric("Throughput Speed", f"{tps:.2f} TPS")
            m3.metric("Avg Engine Latency", f"{avg_latency:.3f} ms")
            
        st.success("Stress benchmark successfully logged! Switch back to the Live Gateway tab to inspect the fresh data streams.")