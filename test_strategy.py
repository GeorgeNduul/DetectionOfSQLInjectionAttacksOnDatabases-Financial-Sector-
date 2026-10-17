import pytest
import numpy as np
from streamlit.testing.v1 import AppTest

# 1. Imports MUST be active in the test file
from app import (
    clean_sql_query,
    extract_single_structural_features,
    initialize_production_environment,
    FinancialDatabaseLedger,
    ForensicQuarantineSystem,
    AutomatedIncidentPreventionGateway
)

# =====================================================================
# PILLAR 1: CORE LOGIC & PIPELINE UNIT TESTS
# =====================================================================

@pytest.fixture
def WAF_gateway():
    """Initializes a clean production environment fixture for testing."""
    model, vectorizer, scaler = initialize_production_environment()
    db = FinancialDatabaseLedger()
    quarantine = ForensicQuarantineSystem()
    return AutomatedIncidentPreventionGateway(model, vectorizer, scaler, db, quarantine)

def test_sql_cleaning_pipeline():
    """Validates that SQL comments, inline blocks, and numbers are cleaned."""
    raw_query = "SELECT * FROM accounts WHERE customer_id = 101 /* inline */ -- comment"
    cleaned = clean_sql_query(raw_query)
    assert "NUM" in cleaned  # Fixed: Checks for uppercase 'NUM'
    assert "comment" not in cleaned
    assert "inline" not in cleaned

def test_feature_extraction_dimensions():
    """Validates feature extraction shape and structural flags."""
    raw_query = "SELECT * FROM card_registry WHERE pin = '123' OR 1=1 --"
    cleaned = clean_sql_query(raw_query)
    features = extract_single_structural_features(cleaned)
    
    assert features.shape == (1, 7)
    assert features[0][2] == 1

def test_safe_transaction_allowed(WAF_gateway):
    """Verifies that legitimate financial ledger queries pass (Status 200)."""
    query = "SELECT balance FROM ledgers WHERE account_num = 4556"
    res = WAF_gateway.process_transaction(query, quiet=True)
    assert res["status"] == 200
    assert "payload" in res["db_response"]

def test_malicious_transaction_blocked(WAF_gateway):
    """Verifies that SQL injection attacks are blocked (Status 403)."""
    query = "SELECT wire_history FROM Swift_logs WHERE id = 1 UNION SELECT password FROM admin"
    res = WAF_gateway.process_transaction(query, quiet=True)
    assert res["status"] == 403
    assert "tx_id" in res  # Fixed: Gateway returns 'tx_id' at root level


# =====================================================================
# PILLAR 2: STREAMLIT UI & STATE TESTING (AppTest)
# =====================================================================

def test_app_launch_initial_state():
    """Tests that the Streamlit app loads with no exceptions and correct header."""
    at = AppTest.from_file("app.py").run()
    assert not at.exception
    assert "Financial Core" in at.title[0].value

def test_live_gateway_safe_query_submission():
    """Simulates user entering a safe query and clicking transmit in Tab 1."""
    at = AppTest.from_file("app.py").run()
    
    at.text_area[0].input("SELECT balance FROM ledgers WHERE account_num = 4556").run()
    
    # Target button safely by label
    transmit_btn = [b for b in at.button if "Transmit Query" in b.label][0]
    transmit_btn.click().run()
    
    assert len(at.success) > 0
    assert "200 OK" in at.success[0].value

def test_live_gateway_attack_quarantine_flow():
    """Simulates an attack submission and verifies state retention in quarantine vault."""
    at = AppTest.from_file("app.py").run()
    
    at.text_area[0].input("SELECT * FROM card_registry WHERE pin = '123' OR 1=1 --").run()
    
    transmit_btn = [b for b in at.button if "Transmit Query" in b.label][0]
    transmit_btn.click().run()
    
    assert len(at.error) > 0
    assert "403 Forbidden" in at.error[0].value
    assert len(at.session_state["quarantine_vault"]) == 1

def test_quarantine_vault_clearing():
    """Simulates navigating to Tab 2 and clearing the forensic repository."""
    at = AppTest.from_file("app.py").run()
    
    # Populate vault first
    at.text_area[0].input("SELECT * FROM card_registry WHERE pin = '123' OR 1=1 --").run()
    transmit_btn = [b for b in at.button if "Transmit Query" in b.label][0]
    transmit_btn.click().run()
    
    # Switch tab and clear
    at.tabs[1].run()
    clear_btn = [b for b in at.button if "Clear Forensic Repository" in b.label][0]
    clear_btn.click().run()
    
    assert len(at.session_state["quarantine_vault"]) == 0


# =====================================================================
# PILLAR 3: PERFORMANCE BENCHMARKING
# =====================================================================

def test_stress_engine_execution():
    """Simulates executing the stress benchmark engine in Tab 3."""
    at = AppTest.from_file("app.py").run()
    
    at.tabs[2].run()
    
    # Target stress button safely by label
    stress_btn = [b for b in at.button if "Execute 1,000 Query Stress Run" in b.label][0]
    stress_btn.click().run()
    
    assert len(at.metric) == 3