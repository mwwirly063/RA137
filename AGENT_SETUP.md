# RA137 AI Agent Setup Guide

Transform the RA137 CLI reconnaissance framework into an interactive AI Agent using **LangChain**, **MCP (Model Context Protocol)**, and **Qwen** LLM.

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the MCP Server](#running-the-mcp-server)
6. [Running the LangChain Agent](#running-the-langchain-agent)
7. [Example Interactions](#example-interactions)
8. [Troubleshooting](#troubleshooting)

---

## 🏗️ Architecture Overview

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   User (CLI)    │ ◄────►  │  LangChain Agent │ ◄────►  │   Qwen LLM      │
│                 │         │  (agent_client)  │         │ (via OpenAI API │
└─────────────────┘         └────────┬─────────┘         │   or Ollama)    │
                                     │                  └─────────────────┘
                                     │ MCP Protocol
                                     ▼
                          ┌──────────────────┐
                          │   MCP Server     │
                          │ (mcp_server.py)  │
                          └────────┬─────────┘
                                   │
                                   ▼
          ┌────────────────────────────────────────┐
          │        RA137 Reconnaissance Modules    │
          │  ┌──────────────┐  ┌────────────────┐  │
          │  │ subdomain_   │  │ tech_detect    │  │
          │  │ enum         │  │                │  │
          │  └──────────────┘  └────────────────┘  │
          │  ┌──────────────┐  ┌────────────────┐  │
          │  │ check_cdn    │  │ network_       │  │
          │  │              │  │ discovery      │  │
          │  └──────────────┘  └────────────────┘  │
          │  ┌──────────────┐                      │
          │  │ vuln_check   │                      │
          │  │ (nuclei)     │                      │
          │  └──────────────┘                      │
          └────────────────────────────────────────┘
```

### Exposed MCP Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| `run_subdomain_enum` | Subdomain enumeration via subfinder & gobuster | First step in recon |
| `run_cdn_analysis` | CDN/Cloud/Hosting detection | Identify proxies vs origin |
| `run_tech_detect` | Technology fingerprinting | Discover frameworks, WAFs |
| `run_network_discovery` | Port scanning & service enumeration | Map attack surface |
| `run_vuln_check` | Nuclei vulnerability scanning | Find exploitable issues |
| `get_recon_summary` | Retrieve existing scan results | Check progress without re-scanning |

---

## ✅ Prerequisites

### System Requirements

- **Python**: 3.10 or higher
- **External Tools** (must be installed separately):
  - `subfinder` - Subdomain enumeration
  - `gobuster` - DNS brute-forcing
  - `nmap` - Port scanning
  - `httpx` / `httpxx` - HTTP probing
  - `gow` / `gowitness` - Screenshot capture
  - `nuclei` - Vulnerability scanning

### Install External Tools (Kali/Debian)

```bash
# Update package list
sudo apt update

# Install nmap
sudo apt install -y nmap

# Install Go (required for ProjectDiscovery tools)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install gobuster
go install -v github.com/OJ/gobuster/v3@latest

# Install gowitness
go install -v github.com/sensepost/gowitness@latest

# Add Go binaries to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 📦 Installation

### Step 1: Clone Repository (if not already done)

```bash
cd /workspace
# Repository is already initialized as a Git repo
```

### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Check Python packages
python -c "import mcp; import langchain; import langchain_openai; print('✓ All packages installed')"

# Check external tools
which subfinder gobuster nmap nuclei httpx
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env  # if template exists
```

Or create manually:

```bash
cat > .env << EOF
# =============================================================================
# LLM Configuration (Choose ONE provider)
# =============================================================================

# Option A: Qwen via OpenAI-compatible endpoint (e.g., Together, vLLM, etc.)
LLM_PROVIDER=openai
LLM_MODEL=qwen-coder
OPENAI_BASE_URL=https://api.together.xyz/v1
OPENAI_API_KEY=your_together_api_key_here

# Option B: Local Ollama with Qwen
# LLM_PROVIDER=ollama
# LLM_MODEL=qwen-coder
# OLLAMA_HOST=http://localhost:11434/v1
# LLM_API_KEY=ollama

# =============================================================================
# External API Keys (Optional - enhances recon capabilities)
# =============================================================================
SHODAN_API_KEY=your_shodan_key
FOFA_EMAIL=your_fofa_email
FOFA_API_KEY=your_fofa_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
SECURITYTRAILS_API_KEY=your_securitytrails_key

# =============================================================================
# Framework Settings
# =============================================================================
HTTP_TIMEOUT=30
API_TIMEOUT=60
MAX_WORKERS=50
EOF
```

### Using Ollama (Local Qwen)

If using local Ollama:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull Qwen model
ollama pull qwen-coder

# Start Ollama server (usually auto-starts)
ollama serve

# Update .env for Ollama
export LLM_PROVIDER=ollama
export LLM_MODEL=qwen-coder
export OLLAMA_HOST=http://localhost:11434/v1
```

---

## 🖥️ Running the MCP Server

The MCP server exposes RA137 modules as tools via the Model Context Protocol.

### Option 1: Direct Execution

```bash
python mcp_server.py
```

The server runs on **stdio** (standard input/output), which is the expected transport for LangChain integration.

### Option 2: Via MCP CLI (Alternative)

```bash
# Install MCP CLI if not already installed
pip install mcp

# Run with MCP inspector for debugging
mcp dev mcp_server.py
```

### Verifying MCP Server

To test the MCP server independently:

```bash
# In one terminal, start the server
python mcp_server.py

# In another terminal, you can use MCP client tools to connect
# (This is handled automatically by agent_client.py)
```

---

## 🤖 Running the LangChain Agent

### Start the Agent

```bash
python agent_client.py
```

This will:
1. Connect to the Qwen LLM (via configured endpoint)
2. Launch the MCP server as a subprocess
3. Initialize the LangChain agent with MCP tools
4. Start an interactive CLI session

### Interactive Session Commands

Once the agent starts, you can:

| Command | Description |
|---------|-------------|
| `exit` / `quit` | End the session |
| `clear` | Clear conversation history |
| `help` | Show agent capabilities |

### Example Interactions

```
🔍 You: Scan example.com for subdomains

🤖 Agent: I'll run subdomain enumeration on example.com...
[Tool call: run_subdomain_enum]
✓ Found 47 subdomains including:
  - www.example.com
  - mail.example.com
  - api.example.com
  - dev.example.com
  ...

🔍 You: Now check what technologies are running on those subdomains

🤖 Agent: I'll perform technology detection...
[Tool call: run_tech_detect]
✓ Technology analysis complete:
  - 23 hosts with detected technologies
  - 3 WAF detections (Cloudflare)
  - Common stack: Nginx, PHP, WordPress

🔍 You: Run a full vulnerability scan

🤖 Agent: I'll execute Nuclei vulnerability scanning...
[Tool call: run_vuln_check]
⚠️ Found 12 vulnerabilities:
  - 2 High severity
  - 5 Medium severity
  - 5 Low severity
  
Critical findings:
  [cve-2024-xxxx] SQL Injection in /admin/login.php
  [exposed-panel] Admin panel publicly accessible
```

### Recommended Workflow

For comprehensive reconnaissance:

1. **Start with subdomain enumeration**
   ```
   "Scan target.com for subdomains"
   ```

2. **Check CDN/proxy status**
   ```
   "Analyze if target.com uses CDN or Cloud providers"
   ```

3. **Discover open ports and services**
   ```
   "Perform network discovery on target.com"
   ```

4. **Identify technologies**
   ```
   "What technologies is target.com using?"
   ```

5. **Run vulnerability assessment**
   ```
   "Scan target.com for vulnerabilities"
   ```

6. **Get summary at any time**
   ```
   "Show me the current recon summary for target.com"
   ```

---

## 🔧 Troubleshooting

### Issue: `langchain-mcp-adapters` not found

```bash
pip install langchain-mcp-adapters
```

If the package is unavailable, see `agent_client_fallback.py` for manual MCP client implementation.

### Issue: LLM connection fails

**For OpenAI-compatible endpoints:**
```bash
# Verify API key and endpoint
curl -X POST https://your-endpoint/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen-coder","messages":[{"role":"user","content":"test"}]}'
```

**For Ollama:**
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Test model
ollama run qwen-coder "Hello"
```

### Issue: External tools not found

```bash
# Verify installations
which subfinder gobuster nmap nuclei httpx gow

# If missing, reinstall following Prerequisites section
```

### Issue: MCP server crashes

Enable verbose logging:

```bash
# Add debug flag
python mcp_server.py 2>&1 | tee mcp_debug.log
```

Check logs for specific error messages.

### Issue: Agent hangs during tool execution

Some recon operations take time. The agent has a 10-minute timeout per execution. For long scans:

```bash
# Increase timeout in agent_client.py
# Edit: max_execution_time=600  →  max_execution_time=1800
```

---

## 📚 Additional Resources

- **MCP Documentation**: https://modelcontextprotocol.io/
- **LangChain Agents**: https://python.langchain.com/docs/modules/agents/
- **Qwen Models**: https://huggingface.co/Qwen
- **RA137 Original Repo**: https://github.com/mwwirly063/RA137

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always ensure you have:

- Written permission from the target owner
- Compliance with applicable laws and regulations
- Understanding of your organization's security policies

Unauthorized scanning is illegal and unethical. Use responsibly.
