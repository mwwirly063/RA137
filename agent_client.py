"""
LangChain Agent Client for RA137 MCP Server.

Connects a LangChain Agent to the RA137 MCP server, enabling interactive
reconnaissance tasks via natural language commands powered by Qwen LLM.

Usage:
    1. Start the MCP server: python mcp_server.py
    2. Run this agent: python agent_client.py
    
Example interactions:
    - "Scan example.com for subdomains"
    - "Check what technologies example.com is using"
    - "Run a vulnerability scan on example.com"
    - "Perform full reconnaissance on example.com starting with subdomain enumeration"
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# LangChain imports
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.memory import ConversationBufferMemory
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema import HumanMessage, SystemMessage

# LangChain MCP integration
try:
    from langchain_mcp_adapters.client import MultiServerMCPClient
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("Warning: langchain-mcp-adapters not installed. Using fallback MCP client.")

# OpenAI-compatible LLM (for Qwen)
try:
    from langchain_openai import ChatOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Error: langchain-openai not installed. Install with: pip install langchain-openai")


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

class AgentConfig:
    """Configuration for the LangChain MCP Agent."""
    
    # LLM Configuration (Qwen via OpenAI-compatible endpoint)
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")  # or "ollama"
    LLM_MODEL: str = os.getenv("LLM_MODEL", "qwen-coder")
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")  # Ollama default
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "not-needed")  # Not needed for local Ollama
    
    # MCP Server Configuration
    MCP_SERVER_COMMAND: list[str] = None
    
    @classmethod
    def init(cls):
        """Initialize configuration based on environment."""
        if cls.LLM_PROVIDER == "ollama":
            cls.LLM_BASE_URL = os.getenv("OLLAMA_HOST", "http://localhost:11434/v1")
            cls.LLM_API_KEY = "ollama"  # Dummy key for Ollama
        elif cls.LLM_PROVIDER == "openai":
            cls.LLM_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
            cls.LLM_API_KEY = os.getenv("OPENAI_API_KEY", "")
        
        # MCP server command - runs the local MCP server
        cls.MCP_SERVER_COMMAND = [
            sys.executable,
            str(Path(__file__).parent / "mcp_server.py"),
        ]


# -----------------------------------------------------------------------------
# System Prompt
# -----------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are RA137 Recon Agent, an intelligent cybersecurity assistant specialized in 
reconnaissance and vulnerability assessment. You have access to powerful security 
scanning tools via the Model Context Protocol (MCP).

## Your Capabilities

You can perform the following reconnaissance tasks:

1. **Subdomain Enumeration** (`run_subdomain_enum`): 
   - Discover subdomains using subfinder (passive) and gobuster (brute-force)
   - This is typically the FIRST step in any reconnaissance engagement
   - Returns a list of discovered subdomains

2. **CDN/Cloud Analysis** (`run_cdn_analysis`):
   - Detect if IPs are behind CDN, Cloud, or Hosting providers
   - Identifies Cloudflare, Akamai, AWS, etc.
   - Helps determine if you're scanning the origin server or a proxy
   - Requires subdomain enumeration to run first (needs pure_ip.txt)

3. **Technology Detection** (`run_tech_detect`):
   - Fingerprint web technologies, frameworks, CMS, servers
   - Detects WAFs, web servers, programming languages
   - Uses httpx for HTTP probing and gowitness for screenshots
   - Returns structured technology data with tags

4. **Network Discovery** (`run_network_discovery`):
   - Port scanning and service enumeration
   - Integrates nmap (local), Shodan, FOFA, Censys, SecurityTrails
   - Returns open ports, services, OS detection
   - ESSENTIAL before vulnerability scanning to identify attack surface

5. **Vulnerability Scanning** (`run_vuln_check`):
   - Run Nuclei vulnerability scanner against discovered IPs
   - Automatically targets open ports from network discovery
   - Returns findings with severity levels (critical/high/medium/low/info)
   - Should be run AFTER network discovery for best results

6. **Recon Summary** (`get_recon_summary`):
   - Check current reconnaissance state without running new scans
   - Retrieve results from previous scans
   - Useful for progress tracking

## Operational Guidelines

### Recommended Reconnaissance Workflow

For comprehensive reconnaissance, follow this sequence:

1. **Start with subdomain enumeration** - Always begin here to discover the attack surface
2. **Run CDN analysis** - Determine which IPs are behind proxies
3. **Perform network discovery** - Find open ports and services
4. **Run technology detection** - Identify technologies and potential weaknesses
5. **Execute vulnerability scan** - Final step to find exploitable issues

### Safety & Ethics

- ONLY scan targets you have explicit authorization to test
- Inform users about the importance of legal authorization
- These tools can generate significant network traffic
- Vulnerability scanning may trigger IDS/IPS alerts
- Always recommend responsible disclosure practices

### Error Handling

- If a tool fails, explain what went wrong and suggest alternatives
- Some tools depend on others (e.g., vuln_check needs network_discovery)
- External API integrations (Shodan, Censys, FOFA) require API keys
- Missing dependencies (nmap, subfinder, nuclei) will cause graceful skips

### Response Style

- Be concise but informative
- Summarize technical results in actionable insights
- Highlight critical findings (WAFs, high-severity vulns, exposed services)
- Suggest next steps in the reconnaissance process
- Use formatting (bullet points, bold text) for readability

## Example Interactions

User: "Scan example.com for subdomains"
→ Call run_subdomain_enum with domain="example.com"
→ Report number of subdomains found and list key discoveries

User: "What's the attack surface for test.com?"
→ Start with run_subdomain_enum, then run_network_discovery
→ Summarize total subdomains, open ports, and exposed services

User: "Check if example.com has vulnerabilities"
→ First ensure network_discovery has been run
→ Then call run_vuln_check
→ Report findings by severity, highlight critical issues

User: "Is example.com behind Cloudflare?"
→ Call run_cdn_analysis
→ Check cdn_ips results for Cloudflare entries

Remember: You are a professional security assistant. Always prioritize 
thoroughness, accuracy, and ethical conduct in your recommendations.
"""


# -----------------------------------------------------------------------------
# MCP Client Setup
# -----------------------------------------------------------------------------

async def create_mcp_tools():
    """
    Create LangChain tools from MCP server.
    
    Uses langchain-mcp-adapters to connect to the MCP server.
    Falls back to manual implementation if package unavailable.
    """
    if not MCP_AVAILABLE:
        raise ImportError(
            "langchain-mcp-adapters is required. Install with:\n"
            "  pip install langchain-mcp-adapters\n"
            "\nOr use the fallback implementation in agent_client_fallback.py"
        )
    
    config = AgentConfig()
    config.init()
    
    # Connect to MCP server via stdio
    client = MultiServerMCPClient(
        {
            "ra137": {
                "command": config.MCP_SERVER_COMMAND[0],
                "args": config.MCP_SERVER_COMMAND[1:],
            }
        }
    )
    
    # Get tools from MCP server
    tools = await client.get_tools()
    
    return tools, client


# -----------------------------------------------------------------------------
# LLM Initialization
# -----------------------------------------------------------------------------

def create_llm() -> Any:
    """
    Initialize the Qwen LLM (or compatible alternative).
    
    Supports:
    - OpenAI-compatible endpoints (including Qwen via vLLM, Together, etc.)
    - Ollama local models
    """
    config = AgentConfig()
    config.init()
    
    if not OPENAI_AVAILABLE:
        raise ImportError(
            "langchain-openai is required. Install with:\n"
            "  pip install langchain-openai"
        )
    
    llm = ChatOpenAI(
        model=config.LLM_MODEL,
        base_url=config.LLM_BASE_URL,
        api_key=config.LLM_API_KEY,
        temperature=0.3,  # Lower temperature for more deterministic outputs
        max_tokens=4096,
        streaming=True,
    )
    
    return llm


# -----------------------------------------------------------------------------
# Agent Creation
# -----------------------------------------------------------------------------

def create_agent(llm: Any, tools: list[Any]) -> AgentExecutor:
    """
    Create the LangChain Agent with tools and memory.
    
    Args:
        llm: Initialized ChatOpenAI instance
        tools: List of MCP-derived tools
    
    Returns:
        Configured AgentExecutor ready for interaction
    """
    # Define the prompt template
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    
    # Create the agent
    agent = create_tool_calling_agent(llm, tools, prompt)
    
    # Add conversation memory
    memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True,
        output_key="output",
    )
    
    # Create the executor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10,
        max_execution_time=600,  # 10 minute timeout per execution
    )
    
    return agent_executor


# -----------------------------------------------------------------------------
# Interactive CLI
# -----------------------------------------------------------------------------

async def run_interactive_session(agent_executor: AgentExecutor):
    """Run an interactive CLI session with the agent."""
    
    print("\n" + "=" * 70)
    print("RA137 Recon Agent - Interactive Session")
    print("=" * 70)
    print("\nAvailable commands:")
    print("  'exit' or 'quit' - End session")
    print("  'clear' - Clear conversation history")
    print("  'help' - Show capabilities")
    print("\nExample: 'Scan example.com for subdomains and check vulnerabilities'")
    print("=" * 70 + "\n")
    
    while True:
        try:
            user_input = input("\n🔍 You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["exit", "quit"]:
                print("\n👋 Ending session. Stay safe!")
                break
            
            if user_input.lower() == "clear":
                agent_executor.memory.clear()
                print("🧹 Conversation history cleared.")
                continue
            
            if user_input.lower() == "help":
                print("\n" + SYSTEM_PROMPT)
                continue
            
            # Execute agent
            print("\n🤖 Agent: ", end="", flush=True)
            
            response = await asyncio.to_thread(
                agent_executor.invoke,
                {"input": user_input}
            )
            
            print(response.get("output", "No response"))
            print()
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted. Type 'exit' to quit.")
            continue
        
        except Exception as e:
            print(f"\n❌ Error: {type(e).__name__}: {e}")
            continue


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

async def main():
    """Main entry point for the LangChain MCP Agent."""
    
    print("🚀 Initializing RA137 Recon Agent...")
    
    try:
        # Step 1: Initialize LLM
        print("📡 Connecting to LLM (Qwen)...")
        llm = create_llm()
        print(f"✓ LLM ready: {llm.model_name}")
        
        # Step 2: Connect to MCP Server and get tools
        print("🔧 Connecting to MCP server...")
        tools, mcp_client = await create_mcp_tools()
        print(f"✓ Connected. Available tools: {len(tools)}")
        for tool in tools:
            print(f"    - {tool.name}")
        
        # Step 3: Create agent
        print("🧠 Creating agent executor...")
        agent_executor = create_agent(llm, tools)
        print("✓ Agent ready")
        
        # Step 4: Run interactive session
        await run_interactive_session(agent_executor)
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("\nInstall required dependencies:")
        print("  pip install langchain langchain-openai langchain-mcp-adapters")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n❌ Fatal Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        print("\n🛑 Shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
