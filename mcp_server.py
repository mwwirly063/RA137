"""
MCP Server for RA137 Reconnaissance Framework.

Exposes core reconnaissance functions as MCP tools, allowing AI agents
to dynamically execute recon tasks via the Model Context Protocol.

Tools Exposed:
    - run_subdomain_enum: Discover subdomains for a target domain
    - run_cdn_analysis: Analyze IPs for CDN/Cloud/Hosting providers
    - run_tech_detect: Detect web technologies and frameworks
    - run_network_discovery: Port scanning and service enumeration
    - run_vuln_check: Run Nuclei vulnerability scans
    - get_recon_summary: Retrieve current recon state/results
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.config import get_config
from utils.paths import create_target_output
from utils.validate import validate_domain
from utils.ip_utils import is_valid_ip

# Import module functions to wrap
from modules.subdomain_enum import collect_subdomains
from modules.check_cdn import filter_non_cdn_ips
from modules.tech_detect import tech_detection
from modules.network_discovery import network_discovery
from modules.vuln_check import nuclei_scan


# -----------------------------------------------------------------------------
# MCP Server Setup
# -----------------------------------------------------------------------------

app = Server("ra137-recon-server")


# -----------------------------------------------------------------------------
# Input Validation Helpers
# -----------------------------------------------------------------------------

def validate_domain_input(domain: str) -> tuple[bool, str]:
    """
    Validate that input is a safe, well-formed domain.
    
    Returns:
        (is_valid, error_message)
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"
    
    domain = domain.strip().lower()
    
    # Remove protocol prefixes if present
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1].split("/")[0]
    
    validated = validate_domain(domain)
    if not validated:
        return False, f"Invalid domain format: {domain}"
    
    return True, ""


def validate_ip_input(ip: str) -> tuple[bool, str]:
    """
    Validate that input is a valid IP address.
    
    Returns:
        (is_valid, error_message)
    """
    if not ip or not isinstance(ip, str):
        return False, "IP must be a non-empty string"
    
    ip = ip.strip()
    
    if not is_valid_ip(ip):
        return False, f"Invalid IP address: {ip}"
    
    return True, ""


# -----------------------------------------------------------------------------
# Async Wrappers for Sync Functions
# -----------------------------------------------------------------------------

async def run_async(func: callable, *args, **kwargs) -> Any:
    """
    Run a synchronous function in an async context using asyncio.to_thread.
    
    This properly offloads blocking I/O operations to a thread pool,
    keeping the event loop responsive.
    """
    return await asyncio.to_thread(func, *args, **kwargs)


# -----------------------------------------------------------------------------
# MCP Tool Definitions
# -----------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="run_subdomain_enum",
            description=(
                "Perform subdomain enumeration for a target domain. "
                "Uses subfinder for passive discovery and gobuster for brute-force DNS enumeration. "
                "Returns a list of discovered subdomains. "
                "This is typically the first step in reconnaissance."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain to enumerate (e.g., 'example.com')",
                    }
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="run_cdn_analysis",
            description=(
                "Analyze IPs to detect CDN, Cloud, or Hosting providers. "
                "Categorizes IPs as CDN, Cloud, Hosting, or Direct (origin). "
                "Useful for determining if a target is behind a proxy/CDN. "
                "Requires prior subdomain enumeration to have generated pure_ip.txt."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain whose IPs should be analyzed",
                    }
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="run_tech_detect",
            description=(
                "Detect web technologies, frameworks, and server software. "
                "Uses httpx for HTTP probing with tech-detect, title extraction, and server headers. "
                "Optionally captures screenshots using gowitness. "
                "Returns structured technology fingerprints including WAF detection."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain to scan for technologies",
                    }
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="run_network_discovery",
            description=(
                "Perform network intelligence gathering including port scanning and service enumeration. "
                "Integrates nmap (local), Shodan, FOFA, Censys, and SecurityTrails. "
                "Returns open ports, services, OS detection, and associated metadata. "
                "Essential for identifying attack vectors before vulnerability scanning."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain for network discovery",
                    }
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="run_vuln_check",
            description=(
                "Run Nuclei vulnerability scanner against discovered IPs. "
                "Automatically builds targets from final_ip.txt and discovered open ports. "
                "Returns vulnerability findings with template IDs and severity. "
                "Should be run after network discovery for optimal port coverage."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain to scan for vulnerabilities",
                    }
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="get_recon_summary",
            description=(
                "Retrieve the current reconnaissance state and results for a target. "
                "Reads JSON result files from previous scans without executing new scans. "
                "Useful for checking progress or retrieving results without re-running tools."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain to get summary for",
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Whether to include full result details (default: false)",
                        "default": False,
                    }
                },
                "required": ["domain"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute an MCP tool with the provided arguments."""
    
    try:
        if name == "run_subdomain_enum":
            return await _handle_subdomain_enum(arguments)
        
        elif name == "run_cdn_analysis":
            return await _handle_cdn_analysis(arguments)
        
        elif name == "run_tech_detect":
            return await _handle_tech_detect(arguments)
        
        elif name == "run_network_discovery":
            return await _handle_network_discovery(arguments)
        
        elif name == "run_vuln_check":
            return await _handle_vuln_check(arguments)
        
        elif name == "get_recon_summary":
            return await _handle_recon_summary(arguments)
        
        else:
            return [TextContent(type="text", text=f"Error: Unknown tool '{name}'")]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"Tool execution failed: {type(exc).__name__}: {exc}"
        )]


# -----------------------------------------------------------------------------
# Tool Handlers
# -----------------------------------------------------------------------------

async def _handle_subdomain_enum(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle run_subdomain_enum tool."""
    domain = arguments.get("domain", "")
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    # Create logger for this operation
    from utils.logger import get_logger
    logger = get_logger("MCP_SUBDOMAIN")
    
    try:
        subdomains = await run_async(
            collect_subdomains,
            domain=domain,
            wordlist_path="wordlists/subdomains.txt",
            output_dir=output_dir,
            target=domain,
        )
        
        result = {
            "status": "success",
            "domain": domain,
            "subdomains_found": len(subdomains),
            "subdomains": sorted(subdomains),
        }
        
        return [TextContent(type="text", text=str(result))]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"Subdomain enumeration failed: {type(exc).__name__}: {exc}"
        )]


async def _handle_cdn_analysis(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle run_cdn_analysis tool."""
    domain = arguments.get("domain", "")
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    from utils.logger import get_logger
    logger = get_logger("MCP_CDN")
    
    try:
        results = await run_async(
            filter_non_cdn_ips,
            output_dir=output_dir,
            logger=logger,
            target=domain,
        )
        
        summary = {
            "status": "success",
            "domain": domain,
            "cdn_ips_count": len(results.get("cdn_ips", [])),
            "cloud_ips_count": len(results.get("cloud_ips", [])),
            "hosting_ips_count": len(results.get("hosting_ips", [])),
            "direct_ips_count": len(results.get("direct_ips", [])),
        }
        
        return [TextContent(type="text", text=str(summary))]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"CDN analysis failed: {type(exc).__name__}: {exc}"
        )]


async def _handle_tech_detect(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle run_tech_detect tool."""
    domain = arguments.get("domain", "")
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    from utils.logger import get_logger
    logger = get_logger("MCP_TECH")
    
    try:
        results = await run_async(
            tech_detection,
            output_dir=output_dir,
            logger=logger,
            target=domain,
        )
        
        # Summarize results
        waf_count = sum(1 for r in results if any(t.startswith("waf:") for t in r.get("tags", [])))
        default_page_count = sum(1 for r in results if any(t.startswith("default:") for t in r.get("tags", [])))
        
        summary = {
            "status": "success",
            "domain": domain,
            "total_results": len(results),
            "waf_detections": waf_count,
            "default_pages": default_page_count,
            "sample_technologies": [
                {"url": r.get("url"), "tags": r.get("tags")}
                for r in results[:10]  # First 10 results
            ],
        }
        
        return [TextContent(type="text", text=str(summary))]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"Technology detection failed: {type(exc).__name__}: {exc}"
        )]


async def _handle_network_discovery(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle run_network_discovery tool."""
    domain = arguments.get("domain", "")
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    from utils.logger import get_logger
    logger = get_logger("MCP_NETWORK")
    
    try:
        results = await run_async(
            network_discovery,
            output_dir=output_dir,
            logger=logger,
            target=domain,
        )
        
        summary = {
            "status": "success",
            "domain": domain,
            "total_ips_scanned": results.get("total_ips_scanned", 0),
            "sources": results.get("sources", {}),
            "nmap_findings_count": len(results.get("results", {}).get("nmap", [])),
            "shodan_findings_count": len(results.get("results", {}).get("shodan", [])),
        }
        
        return [TextContent(type="text", text=str(summary))]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"Network discovery failed: {type(exc).__name__}: {exc}"
        )]


async def _handle_vuln_check(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle run_vuln_check tool."""
    domain = arguments.get("domain", "")
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    from utils.logger import get_logger
    logger = get_logger("MCP_VULN")
    
    try:
        findings = await run_async(
            nuclei_scan,
            output_dir=output_dir,
            logger=logger,
            target=domain,
        )
        
        # Categorize findings by severity (if available in raw output)
        severity_counts: Dict[str, int] = {}
        for finding in findings:
            raw = finding.get("raw", "").lower()
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in raw:
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    break
        
        summary = {
            "status": "success",
            "domain": domain,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "sample_findings": [
                {"template": f.get("template"), "raw": f.get("raw")[:200]}
                for f in findings[:5]  # First 5 findings
            ],
        }
        
        return [TextContent(type="text", text=str(summary))]
    
    except Exception as exc:
        return [TextContent(
            type="text",
            text=f"Vulnerability scan failed: {type(exc).__name__}: {exc}"
        )]


async def _handle_recon_summary(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle get_recon_summary tool."""
    import json
    
    domain = arguments.get("domain", "")
    include_details = arguments.get("include_details", False)
    
    is_valid, error = validate_domain_input(domain)
    if not is_valid:
        return [TextContent(type="text", text=f"Validation error: {error}")]
    
    config = get_config()
    output_dir = create_target_output(domain, config.paths.output_base)
    
    summary_data: Dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "output_directory": str(output_dir),
        "available_results": [],
    }
    
    # Check for result files from various modules
    result_files = {
        "subdomains": output_dir / "subdomains.txt",
        "cdn_analysis": output_dir / "cdn" / "cdn_analysis.json",
        "tech_results": output_dir / "tech" / "tech_results.json",
        "network_results": output_dir / "network" / "network_results.json",
        "vuln_results": output_dir / "vulns" / "vuln_results.json",
        "final_ips": output_dir / "final" / "final_ip.txt",
    }
    
    for name, filepath in result_files.items():
        if filepath.exists():
            file_info = {"name": name, "path": str(filepath), "size_bytes": filepath.stat().st_size}
            
            if include_details and filepath.suffix == ".json":
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        file_info["content"] = json.load(f)
                except Exception:
                    pass
            
            summary_data["available_results"].append(file_info)
    
    return [TextContent(type="text", text=str(summary_data))]


# -----------------------------------------------------------------------------
# Server Entry Point
# -----------------------------------------------------------------------------

async def main() -> None:
    """Run the MCP server using stdio transport."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
