import os
import random
import pandas as pd
from datetime import datetime, timedelta

random.seed(42)
csv_path = r"C:\Users\HP\Documents\majorproject\financial_sqli_master_10k.csv"
os.makedirs(os.path.dirname(csv_path), exist_ok=True)

# Attack Signatures matching your Literature Review
payloads = {
    "Tautology": ["' OR '1'='1", "' OR TRUE --", "' OR 'x'='x", "\" OR \"\"=\"\""],
    "UNION based": ["' UNION SELECT null, username, password_hash FROM bank_users; --", "' UNION SELECT card_number, csv_code FROM credit_cards; --"],
    "Piggyback": ["; DROP TABLE financial_transactions; --", "; UPDATE accounts SET balance = 999999 WHERE user_id = 101; --"],
    "Blind": ["'; WAITFOR DELAY '0:0:5'; --", "' AND SLEEP(5); --", "'; IF(1=1) RoyalBank_Sleep(); --"],
    "Error based": ["' AND convert(int,@@version) --", "' AND EXSTRUCT(1, (SELECT username FROM bank_users)) --"]
}

contexts = ["Authentication", "Account_Balances", "Transaction_History", "Card_Processing", "Auditing"]
rows = []
base_time = datetime(2026, 6, 24, 6, 0, 0)

print("Generating 10,000 highly diversified financial query rows...")

# 1. Generate 5,000 Legitimate Financial Queries
for i in range(1, 5001):
    record_time = (base_time + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S')
    ctx = random.choice(contexts)
    raw_q = f"SELECT balance FROM accounts WHERE user_id = {random.randint(1000, 9999)} AND branch = 'LN_01';"
    rows.append([i, raw_q, len(raw_q), len(raw_q.split()), "false", 0, 2, "Normal", False, record_time, ctx])

# 2. Generate 5,000 Malicious Queries distributed evenly across all 5 Literature Review types
attack_types = ["Tautology", "UNION based", "Piggyback", "Blind", "Error based"]
current_id = 5001

for attack in attack_types:
    for _ in range(1000): # 1,000 rows per type x 5 types = 5,000 rows
        record_time = (base_time + timedelta(seconds=current_id)).strftime('%Y-%m-%d %H:%M:%S')
        ctx = random.choice(contexts)
        payload = random.choice(payloads[attack])
        
        if attack == "Tautology":
            raw_q = f"SELECT * FROM bank_users WHERE username = 'admin{payload}';"
        elif attack == "UNION based":
            raw_q = f"SELECT balance FROM accounts WHERE account_number = '123{payload}';"
        elif attack == "Piggyback":
            raw_q = f"SELECT amount FROM transactions WHERE id = 45{payload};"
        elif attack == "Blind":
            raw_q = f"SELECT credit_limit FROM credit_cards WHERE card_num = '4111'{payload};"
        else: # Error based
            raw_q = f"SELECT * FROM accounts WHERE id = '99'{payload};"
            
        has_taut = "true" if attack == "Tautology" else "false"
        union_cnt = 1 if attack == "UNION based" else 0
        spec_cnt = sum(1 for c in raw_q if c in ["'", "\"", "-", ";", "(", ")"])
        
        rows.append([current_id, raw_q, len(raw_q), len(raw_q.split()), has_taut, union_cnt, spec_cnt, attack, True, record_time, ctx])
        current_id += 1

columns = ["query_id", "raw_query", "query_length", "token_count", "has_tautology", "union_keyword_count", "special_char_count", "attack_type", "is_malicious", "created_at", "financial_context"]
df = pd.DataFrame(rows, columns=columns).sample(frac=1, random_state=42) # Shuffle rows
df.to_csv(csv_path, index=False)

print(f"File successfully overwritten at: {csv_path}")
print(df["attack_type"].value_counts())