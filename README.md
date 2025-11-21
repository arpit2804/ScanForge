```md
# ScanForge

**AI-Powered Vulnerability Scanner with Model Context Protocol (MCP)**

ScanForge is an intelligent vulnerability scanning system that leverages Large Language Models (LLMs) to perform context-aware security testing. Unlike traditional scanners with hardcoded patterns, ScanForge uses AI reasoning to generate adaptive payloads, analyze responses intelligently, and orchestrate comprehensive security assessments.

## 🌟 Key Features

- **AI-Powered Intelligence**: Uses Groq LLMs for dynamic payload generation and intelligent vulnerability detection
- **MCP Architecture**: Clean separation between AI reasoning (agent) and scanning operations (MCP server)
- **Context-Aware Testing**: Generates payloads based on target context (frameworks, parameters, input types)
- **Adaptive Analysis**: AI-driven response analysis that understands subtle vulnerability indicators
- **Built-in Safety**: Rate limiting, scope validation, and dangerous payload detection
- **Web Interface**: Modern chat-based UI for interactive security testing
- **Comprehensive Crawling**: Automatic discovery of endpoints, forms, and attack surface

## 🏗️ Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Web UI        │────────>│  Chat Server     │────────>│  VulnScanAgent  │
│  (index.html)   │         │  (Port 8001)     │         │  (AI Brain)     │
└─────────────────┘         └──────────────────┘         └─────────────────┘
                                                                   │
                                                                   │ Uses AI to
                                                                   │ decide actions
                                                                   ▼
                                                          ┌─────────────────┐
                                                          │  AIInterface    │
                                                          │  (Groq LLM)     │
                                                          └─────────────────┘
                                                                   │
                                                                   │ Calls tools
                                                                   ▼
                                                          ┌─────────────────┐
                                                          │  MCP Server     │
                                                          │  (Port 8000)    │
                                                          │  - Crawling     │
                                                          │  - Injection    │
                                                          │  - Analysis     │
                                                          │  - Storage      │
                                                          └─────────────────┘
```

## 📋 Prerequisites

- Python 3.8+
- A [Groq API key](https://console.groq.com/) (free tier available)
- Basic understanding of web security concepts

## 🚀 Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd ScanForge
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API credentials:**

Create a `src/config.py` file with your Groq API key:

```python
import os

# =============================================================================
# Groq LLM API Configuration 
# =============================================================================

# Your Groq API key - get one from https://console.groq.com/
GROQ_API_KEY = "your-api-key-here"

# The model you want to use with the Groq API
# Recommended: "llama-3.3-70b-versatile" or "llama-3.1-70b-versatile"
GROQ_MODEL = "llama-3.3-70b-versatile"

# =============================================================================
# Other Configurations
# =============================================================================

REQUESTS_PER_MINUTE = 30
```

**Alternative:** Set environment variables instead:
```bash
export GROQ_API_KEY="your-api-key-here"
export GROQ_MODEL="llama-3.3-70b-versatile"
```

## 🎯 Running ScanForge

### Option 1: Using Startup Script (Recommended)

Create a startup script to run both servers:

**For Linux/Mac (`start.sh`):**
```bash
#!/bin/bash

echo "Starting ScanForge..."
echo "===================="

# Start MCP Server
echo "Starting MCP Server on port 8000..."
uvicorn mcp_server_app:app --host 127.0.0.1 --port 8000 &
MCP_PID=$!

# Wait for MCP server to start
sleep 3

# Start Chat Server
echo "Starting Chat Server on port 8001..."
uvicorn chat_server:app --host 0.0.0.0 --port 8001 &
CHAT_PID=$!

echo ""
echo "✅ ScanForge is running!"
echo "📡 MCP Server: http://127.0.0.1:8000"
echo "💬 Chat Server: http://localhost:8001"
echo "🌐 Web UI: Open index.html in your browser"
echo ""
echo "To stop: kill $MCP_PID $CHAT_PID"

# Wait for both processes
wait
```

Make it executable and run:
```bash
chmod +x start.sh
./start.sh
```

**For Windows (`start.bat`):**
```batch
@echo off
echo Starting ScanForge...
echo ====================

echo Starting MCP Server on port 8000...
start "MCP Server" uvicorn mcp_server_app:app --host 127.0.0.1 --port 8000

timeout /t 3 /nobreak >nul

echo Starting Chat Server on port 8001...
start "Chat Server" uvicorn chat_server:app --host 0.0.0.0 --port 8001

echo.
echo ✅ ScanForge is running!
echo 📡 MCP Server: http://127.0.0.1:8000
echo 💬 Chat Server: http://localhost:8001
echo 🌐 Web UI: Open index.html in your browser
echo.
echo Press Ctrl+C in each window to stop
```

Run it:
```batch
start.bat
```

### Option 2: Running Servers Independently

**Terminal 1 - Start MCP Server:**
```bash
uvicorn mcp_server_app:app --host 127.0.0.1 --port 8000
```

**Terminal 2 - Start Chat Server:**
```bash
uvicorn chat_server:app --host 0.0.0.0 --port 8001
```

**Terminal 3 - Open Web UI:**
```bash
# Open index.html in your browser
# Or use a simple HTTP server:
python -m http.server 8080
# Then navigate to: http://localhost:8080/index.html
```

## 💻 Usage

### Web Interface

1. Open `index.html` in your browser
2. Start a conversation with example commands:
   - "Scan https://httpbin.org/forms/post for XSS"
   - "Generate 5 SQL injection payloads for a login form"
   - "Crawl https://example.com and find forms"

### Programmatic Usage

Edit the goal in `src/main.py` and run:

```python
# Example: Comprehensive scan
goal = "Validate and perform a comprehensive scan for XSS and SQLi on 'https://httpbin.org/forms/post'. Be thorough."

# Example: Intelligent payload generation
goal = "Generate 5 context-aware XSS payloads for an email input field in a React application"

# Example: Simple request
goal = "Just get me 3 SQLi payloads for a 'username' parameter"
```

Then run:
```bash
python -m src.main
```

## 📁 Project Structure

```
ScanForge/
├── src/
│   ├── main.py              # Core MCP server and agent logic
│   ├── AIInterface.py       # LLM interface and AI-powered tools
│   └── config.py            # Configuration (API keys, models)
├── mcp_server_app.py        # FastAPI MCP server endpoint
├── chat_server.py           # Chat interface backend
├── index.html               # Web UI
├── evaluate_analysis.py     # Evaluation script for AI analysis
├── evaluate_payload_safety.py # Payload safety testing
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── output/                 # Scan results and findings (auto-created)
```

## 🎓 Example Workflows

### 1. Full Security Assessment
```
"Perform a comprehensive security assessment on https://testsite.com including:
1. Crawl the site to discover endpoints
2. Test for XSS in all forms
3. Test for SQL injection in query parameters
4. Report all findings"
```

### 2. Targeted Testing
```
"Test the login form at https://example.com/login for:
- SQL injection in username/password
- XSS in error messages
Use 5 payloads for each vulnerability type"
```

### 3. Payload Generation
```
"Generate 10 advanced XSS payloads that:
- Bypass common WAF filters
- Target modern frameworks like React
- Include polyglot variants"
```

## 🔒 Safety Features

- **Scope Validation**: Ensures testing stays within allowed domains
- **Rate Limiting**: Prevents overwhelming target servers (30 req/min default)
- **Dangerous Payload Detection**: Blocks destructive operations
- **Request Timeouts**: Prevents hanging operations
- **Crawl Limits**: Max depth and page limits to prevent infinite crawling

## 📊 Output

Findings are saved to the `output/` directory as JSON files:

```json
{
  "type": "xss",
  "severity": "high",
  "title": "Reflected XSS in search parameter",
  "description": "User input reflected without sanitization",
  "location": {
    "url": "https://example.com/search",
    "parameter": "q"
  },
  "evidence": {
    "payload": "<script>alert(1)</script>",
    "response": "..."
  },
  "confidence": 0.95,
  "timestamp": 1234567890
}
```

## 🧪 Evaluation

Test the AI components:

```bash
# Test vulnerability analysis accuracy
python evaluate_analysis.py

# Test payload safety
python evaluate_payload_safety.py
```

## ⚙️ Configuration Options

Edit `src/config.py` to customize:

- `GROQ_API_KEY`: Your API key
- `GROQ_MODEL`: LLM model to use
- `REQUESTS_PER_MINUTE`: Rate limiting threshold

Adjust in code:
- **Crawl depth**: `depth` parameter in `crawl_site` (default: 2, max: 3)
- **Max payloads**: `count` parameter in `get_payloads` (default: 10, max: 50)
- **Timeout values**: Various timeout parameters in `main.py`

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional vulnerability types
- Enhanced AI prompts
- More sophisticated crawling logic
- Export formats (PDF, HTML reports)
- Integration with CI/CD pipelines

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is intended for:
- Testing systems you own
- Authorized penetration testing engagements
- Educational purposes in controlled environments

**Unauthorized testing is illegal.** Always obtain explicit written permission before testing any system you don't own.

## 📝 License

[Add your license here]

## 🙏 Acknowledgments

- Built with [Groq](https://groq.com/) for fast LLM inference
- Uses [FastAPI](https://fastapi.tiangolo.com/) for server components
- Inspired by the Model Context Protocol architecture

---

**Happy (Authorized) Hacking! 🔐**
```
