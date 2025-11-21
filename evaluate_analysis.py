import asyncio
import random
import os
import sys
from typing import List, Dict, Any
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Now import directly (not 'from src.AIInterface')
from AIInterface import AIInterface

# =============================================================================
# 1. DATASET GENERATOR
# =============================================================================

def generate_padding(target_length: int = 1000) -> str:
    """Generates benign HTML padding to reach target length."""
    lorem = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
        "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
        "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
        "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
        "culpa qui officia deserunt mollit anim id est laborum. "
        "<div><span><p>Page footer content and copyright info.</p></span></div>"
    )
    while len(lorem) < target_length:
        lorem += lorem
    return lorem[:target_length]

def generate_dataset() -> List[Dict[str, Any]]:
    """Generates 35 Vulnerable and 30 Safe HTTP responses."""
    dataset = []
    padding = generate_padding(1200)  # Generate enough padding

    # --- VULNERABLE SAMPLES (35 Total) ---
    
    # 1. SQL Injection (18 samples)
    sqli_patterns = [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given",
        "ORA-00933: SQL command not properly ended",
        "PSQLException: ERROR: unterminated quoted string at or near",
        "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'",
        "Unclosed quotation mark after the character string",
        "SQLSTATE[42000]: Syntax error or access violation",
        "driver.jdbc.fbc.SQLError: [SQLITE_ERROR] SQL error or missing database",
        "org.hibernate.exception.SQLGrammarException: could not execute query",
        "System.Data.SqlClient.SqlException: Incorrect syntax near",
    ]
    
    for i in range(18):
        error = random.choice(sqli_patterns)
        # Embed error in valid HTML
        body = f"<html><body><h1>Search Results</h1><div class='error'>{error}</div><p>{padding}</p></body></html>"
        dataset.append({
            "type": "sqli",
            "is_vuln": True,
            "response_body": body[:1000], # Trim to exact length
            "payload": "' OR '1'='1"
        })

    # 2. XSS (17 samples)
    xss_patterns = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\";alert('XSS');//",
        "<iframe src=javascript:alert(1)></iframe>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ]

    for i in range(17):
        payload = random.choice(xss_patterns)
        # Embed payload in input value or raw text
        body = f"<html><body><h1>Welcome</h1><input value='{payload}'><div>{padding}</div></body></html>"
        dataset.append({
            "type": "xss",
            "is_vuln": True,
            "response_body": body[:1000],
            "payload": payload
        })

    # --- SAFE SAMPLES (30 Total) ---

    # 1. Safe SQLI checks (15 samples)
    safe_content = [
        "Search results: 0 items found.",
        "Invalid username or password.",
        "Product not found.",
        "Internal Server Error (500) - Generic error page (no SQL dump)",
        "Welcome back, user ' OR '1'='1.", # Payload reflected safely as text
        "Maintenance mode enabled.",
    ]

    for i in range(15):
        content = random.choice(safe_content)
        body = f"<html><body><h1>Info</h1><p>{content}</p><p>{padding}</p></body></html>"
        dataset.append({
            "type": "sqli",
            "is_vuln": False,
            "response_body": body[:1000],
            "payload": "' OR '1'='1"
        })

    # 2. Safe XSS checks (15 samples)
    for i in range(15):
        # Sanitized outputs
        content = "&lt;script&gt;alert(1)&lt;/script&gt;" 
        body = f"<html><body><h1>Search for: {content}</h1><p>{padding}</p></body></html>"
        dataset.append({
            "type": "xss",
            "is_vuln": False,
            "response_body": body[:1000],
            "payload": "<script>alert(1)</script>"
        })

    random.shuffle(dataset)
    return dataset

# =============================================================================
# 2. EVALUATION LOGIC
# =============================================================================

async def evaluate_model():
    print("Initializing AI Interface...")
    try:
        ai = AIInterface()
    except Exception as e:
        print(f"Error initializing AI: {e}")
        print("Make sure your API key is set in config.py or environment variables.")
        return

    dataset = generate_dataset()
    total_samples = len(dataset)
    print(f"\nGenerated {total_samples} samples (35 Vuln, 30 Safe). Evaluation starting...")
    print("=" * 60)
    print(f"{'ID':<4} | {'Type':<6} | {'Actual':<10} | {'Predicted':<10} | {'Result':<10}")
    print("-" * 60)

    tp, tn, fp, fn = 0, 0, 0, 0
    
    for i, case in enumerate(dataset):
        # Construct arguments for analyze_vulnerability
        request_data = {"payload": case["payload"], "target": "http://test.local"}
        response_data = {"status_code": 200, "body": case["response_body"]}
        vuln_type = case["type"]

        # Call the model
        try:
            prediction = await ai.analyze_response_with_ai(request_data, response_data)
        except Exception as e:
            print(f"Error on sample {i}: {e}")
            prediction = False # Default to safe on error

        # Calculate metrics
        prediction = prediction["vulnerability_detected"]
        actual = case["is_vuln"]
        is_correct = (prediction == actual)
        
        if actual and prediction: tp += 1
        if not actual and not prediction: tn += 1
        if not actual and prediction: fp += 1
        if actual and not prediction: fn += 1

        # Visualization logic
        result_str = "✅ PASS" if is_correct else "❌ FAIL"
        act_str = "VULN" if actual else "SAFE"
        pred_str = "VULN" if prediction else "SAFE"
        
        print(f"{i+1:<4} | {vuln_type.upper():<6} | {act_str:<10} | {pred_str:<10} | {result_str:<10}")

    # =============================================================================
    # 3. RESULTS & METRICS
    # =============================================================================
    
    accuracy = (tp + tn) / total_samples
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print("=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    print(f"Total Samples: {total_samples}")
    print(f"True Positives (Correctly found vuln): {tp}")
    print(f"True Negatives (Correctly ignored safe): {tn}")
    print(f"False Positives (False Alarm): {fp}")
    print(f"False Negatives (Missed Vuln): {fn}")
    print("-" * 30)
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%} (How trustworthy are the alerts?)")
    print(f"Recall:    {recall:.2%} (How many vulns did we catch?)")
    print(f"F1 Score:  {f1_score:.2f}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(evaluate_model())