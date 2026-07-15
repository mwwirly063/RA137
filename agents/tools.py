"""
LangChain tools wrapping RA137 reconnaissance modules.

Provides Tool instances for all reconnaissance capabilities:
- Subdomain enumeration
- IP extraction and analysis
- CDN detection
- Certificate discovery
- Real IP discovery
- ASN reconnaissance
- Technology detection
- Network discovery
- Vulnerability scanning
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type
from functools import wraps

from langchain_core.tools import BaseTool, tool


class ReconTools:
    """
    Factory class for creating LangChain tools from reconnaissance modules.
    
    Usage:
        tools = ReconTools.create_all_tools()
        agent = create_react_agent(llm, tools)
    """
    
    @staticmethod
    def _wrap_async(func: Callable) -> Callable:
        """Wrap a sync function to be async-compatible."""
        if asyncio.iscoroutinefunction(func):
            return func
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
        
        return async_wrapper
    
    @staticmethod
    @tool
    async def enumerate_subdomains(domain: str) -> str:
        """
        Enumerate subdomains for a given domain using subfinder and gobuster.
        
        Parameters
        ----------
        domain : str
            Target domain to enumerate (e.g., "example.com")
            
        Returns
        -------
        str
            Newline-separated list of discovered subdomains
        """
        try:
            from modules.subdomain_enum import collect_subdomains
            from utils.paths import create_target_output
            from utils.config import get_config
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            
            subdomains = collect_subdomains(
                domain=domain,
                wordlist_path="wordlists/subdomains.txt",
                output_dir=output_dir,
                target=domain,
            )
            
            if subdomains:
                return "\n".join(sorted(subdomains))
            return "No subdomains found"
            
        except Exception as e:
            return f"Error enumerating subdomains: {str(e)}"
    
    @staticmethod
    @tool
    async def extract_ips(domain: str) -> str:
        """
        Extract IP addresses from DNS resolution of subdomains.
        
        Parameters
        ----------
        domain : str
            Target domain whose subdomains to resolve
            
        Returns
        -------
        str
            Newline-separated list of unique IP addresses
        """
        try:
            from modules.ip_extractor import collect_ips
            from utils.paths import create_target_output
            from utils.config import get_config
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            
            # Ensure subdomains exist first
            if not (output_dir / "subdomains.txt").exists():
                sub_result = await ReconTools.enumerate_subdomains.invoke({"domain": domain})
            
            ips = collect_ips(output_dir=output_dir, target=domain)
            
            if ips:
                return "\n".join(sorted(set(str(ip) for ip in ips)))
            return "No IPs found"
            
        except Exception as e:
            return f"Error extracting IPs: {str(e)}"
    
    @staticmethod
    @tool
    async def detect_cdn(domain: str) -> str:
        """
        Detect CDN, cloud, and hosting providers for target IPs.
        
        Parameters
        ----------
        domain : str
            Target domain to analyze
            
        Returns
        -------
        str
            CDN analysis results with provider information
        """
        try:
            from modules.check_cdn import filter_non_cdn_ips
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("CDN-AGENT")
            
            # Ensure IPs exist first
            if not (output_dir / "ips.txt").exists():
                await ReconTools.extract_ips.invoke({"domain": domain})
            
            filter_non_cdn_ips(output_dir=output_dir, logger=logger, target=domain)
            
            cdn_file = output_dir / "cdn_analysis.txt"
            if cdn_file.exists():
                return cdn_file.read_text(encoding="utf-8")
            return "CDN analysis completed - check output directory"
            
        except Exception as e:
            return f"Error detecting CDN: {str(e)}"
    
    @staticmethod
    @tool
    async def discover_certificates(domain: str) -> str:
        """
        Discover SSL/TLS certificates and extract domains from them.
        
        Parameters
        ----------
        domain : str
            Target domain to scan
            
        Returns
        -------
        str
            Certificate discovery results with CN and SAN information
        """
        try:
            from modules.cert_discovery import cert_discovery
            from utils.paths import create_target_output
            from utils.config import get_config
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            
            cert_discovery(target=domain, output_dir=output_dir)
            
            cert_file = output_dir / "certificates.txt"
            if cert_file.exists():
                return cert_file.read_text(encoding="utf-8")
            return "Certificate discovery completed - check output directory"
            
        except Exception as e:
            return f"Error discovering certificates: {str(e)}"
    
    @staticmethod
    @tool
    async def discover_real_ip(domain: str) -> str:
        """
        Discover origin IP addresses behind CDN protection.
        
        Parameters
        ----------
        domain : str
            Target domain to analyze
            
        Returns
        -------
        str
            Real IP discovery results with confidence scores
        """
        try:
            from modules.realip_discovery import real_ip_discovery
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("REALIP-AGENT")
            
            real_ip_discovery(output_dir=output_dir, logger=logger, target=domain)
            
            realip_file = output_dir / "real_ips.txt"
            if realip_file.exists():
                return realip_file.read_text(encoding="utf-8")
            return "Real IP discovery completed - check output directory"
            
        except Exception as e:
            return f"Error discovering real IP: {str(e)}"
    
    @staticmethod
    @tool
    async def recon_asn(domain: str) -> str:
        """
        Perform ASN and IP range reconnaissance.
        
        Parameters
        ----------
        domain : str
            Target domain to analyze
            
        Returns
        -------
        str
            ASN reconnaissance results with organization and prefix information
        """
        try:
            from modules.asn_recon import asn_recon
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("ASN-AGENT")
            
            asn_recon(output_dir=output_dir, target=domain, logger=logger)
            
            asn_file = output_dir / "asn_recon.txt"
            if asn_file.exists():
                return asn_file.read_text(encoding="utf-8")
            return "ASN reconnaissance completed - check output directory"
            
        except Exception as e:
            return f"Error in ASN reconnaissance: {str(e)}"
    
    @staticmethod
    @tool
    async def detect_technologies(domain: str) -> str:
        """
        Detect web technologies, frameworks, and WAFs.
        
        Parameters
        ----------
        domain : str
            Target domain to analyze
            
        Returns
        -------
        str
            Technology detection results with server info and detected technologies
        """
        try:
            from modules.tech_detect import tech_detection
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("TECH-AGENT")
            
            tech_detection(output_dir=output_dir, logger=logger, target=domain)
            
            tech_file = output_dir / "technologies.txt"
            if tech_file.exists():
                return tech_file.read_text(encoding="utf-8")
            return "Technology detection completed - check output directory"
            
        except Exception as e:
            return f"Error detecting technologies: {str(e)}"
    
    @staticmethod
    @tool
    async def discover_network(domain: str) -> str:
        """
        Discover network infrastructure from multiple intelligence sources.
        
        Parameters
        ----------
        domain : str
            Target domain to analyze
            
        Returns
        -------
        str
            Network discovery results from NMAP, Shodan, FOFA, Censys, SecurityTrails
        """
        try:
            from modules.network_discovery import network_discovery
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("NETWORK-AGENT")
            
            network_discovery(output_dir=output_dir, logger=logger, target=domain)
            
            network_file = output_dir / "network_discovery.txt"
            if network_file.exists():
                return network_file.read_text(encoding="utf-8")
            return "Network discovery completed - check output directory"
            
        except Exception as e:
            return f"Error in network discovery: {str(e)}"
    
    @staticmethod
    @tool
    async def scan_vulnerabilities(domain: str) -> str:
        """
        Scan for vulnerabilities using Nuclei.
        
        Parameters
        ----------
        domain : str
            Target domain to scan
            
        Returns
        -------
        str
            Vulnerability scan results with severity information
        """
        try:
            from modules.vuln_check import nuclei_scan
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("VULN-AGENT")
            
            nuclei_scan(output_dir=output_dir, logger=logger, target=domain)
            
            vuln_file = output_dir / "vulnerabilities.txt"
            if vuln_file.exists():
                return vuln_file.read_text(encoding="utf-8")
            return "Vulnerability scan completed - check output directory"
            
        except Exception as e:
            return f"Error scanning vulnerabilities: {str(e)}"
    
    @staticmethod
    @tool
    async def aggregate_findings(domain: str) -> str:
        """
        Aggregate all findings into a final IP list.
        
        Parameters
        ----------
        domain : str
            Target domain to aggregate findings for
            
        Returns
        -------
        str
            Final aggregated IP and CIDR list
        """
        try:
            from modules.final_ip_builder import build_final_ips
            from utils.paths import create_target_output
            from utils.config import get_config
            from utils.logger import get_logger
            
            config = get_config()
            output_dir = create_target_output(domain, config.paths.output_base)
            logger = get_logger("AGGREGATOR")
            
            build_final_ips(output_dir=output_dir, logger=logger, target=domain)
            
            final_file = output_dir / "final_ips.txt"
            if final_file.exists():
                return final_file.read_text(encoding="utf-8")
            return "IP aggregation completed - check output directory"
            
        except Exception as e:
            return f"Error aggregating findings: {str(e)}"
    
    @classmethod
    def create_all_tools(cls) -> List[BaseTool]:
        """
        Create all available reconnaissance tools.
        
        Returns
        -------
        List[BaseTool]
            List of LangChain Tool instances
        """
        return [
            cls.enumerate_subdomains,
            cls.extract_ips,
            cls.detect_cdn,
            cls.discover_certificates,
            cls.discover_real_ip,
            cls.recon_asn,
            cls.detect_technologies,
            cls.discover_network,
            cls.scan_vulnerabilities,
            cls.aggregate_findings,
        ]
    
    @classmethod
    def create_tool_by_name(cls, name: str) -> Optional[BaseTool]:
        """
        Get a specific tool by name.
        
        Parameters
        ----------
        name : str
            Tool name (e.g., "enumerate_subdomains")
            
        Returns
        -------
        BaseTool or None
            The requested tool, or None if not found
        """
        tools = {t.name: t for t in cls.create_all_tools()}
        return tools.get(name)
