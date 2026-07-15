"""
LangChain-based planning agent for reconnaissance workflows.

Provides:
- ReconPlanner: Creates and executes structured recon plans using LangChain
- Automatic step sequencing based on target analysis
- Dynamic plan adjustment based on findings
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage


class ReconPlanner:
    """
    AI-powered planner for reconnaissance workflows.
    
    Uses LangChain to:
    - Analyze the target and determine optimal reconnaissance steps
    - Create an ordered execution plan
    - Adjust the plan dynamically based on intermediate findings
    - Generate executive summaries of results
    
    The planner works with LangChain agents to execute the planned steps
    using the tools provided by ReconTools.
    """
    
    # Standard reconnaissance workflow steps in dependency order
    STANDARD_STEPS = [
        "enumerate_subdomains",
        "extract_ips", 
        "detect_cdn",
        "discover_certificates",
        "discover_real_ip",
        "recon_asn",
        "aggregate_findings",
        "detect_technologies",
        "discover_network",
        "scan_vulnerabilities",
    ]
    
    def __init__(
        self,
        llm: Optional[Any] = None,
        verbose: bool = True,
    ):
        """
        Initialize the reconnaissance planner.
        
        Parameters
        ----------
        llm : Any, optional
            LangChain LLM instance (default: auto-created)
        verbose : bool
            Whether to print detailed planning information
        """
        self.llm = llm or self._create_llm()
        self.verbose = verbose
        self.parser = JsonOutputParser()
    
    def _create_llm(self) -> Any:
        """Create an LLM instance from configuration."""
        try:
            from utils.config import get_config
            config = get_config()
            
            if config.ai.provider.lower() == "ollama":
                from langchain_ollama import ChatOllama
                return ChatOllama(
                    model=config.ai.model or "llama3",
                    base_url=config.ai.base_url or "http://localhost:11434",
                    temperature=0.2,
                )
            else:
                from langchain_openai import ChatOpenAI
                kwargs = {
                    "model": config.ai.model or "gpt-4o-mini",
                    "temperature": 0.2,
                }
                if config.ai.api_key:
                    kwargs["api_key"] = config.ai.api_key
                if config.ai.base_url:
                    kwargs["base_url"] = config.ai.base_url
                return ChatOpenAI(**kwargs)
                
        except ImportError as e:
            raise ImportError(
                "LangChain packages not installed. "
                "Run: pip install langchain langchain-openai langchain-ollama"
            ) from e
    
    def create_planning_prompt(self, target: str, context: Optional[str] = None) -> ChatPromptTemplate:
        """
        Create a prompt template for generating reconnaissance plans.
        
        Parameters
        ----------
        target : str
            Target domain or IP
        context : str, optional
            Additional context about the target or engagement
            
        Returns
        -------
        ChatPromptTemplate
            Configured prompt template for planning
        """
        system_message = f"""You are an expert cybersecurity reconnaissance planner.

Your task is to create optimal reconnaissance plans for analyzing targets.

Available reconnaissance steps (in typical dependency order):
{chr(10).join(f"- {step}" for step in self.STANDARD_STEPS)}

Planning Guidelines:
1. Always start with subdomain enumeration to discover the attack surface
2. Extract IPs before running CDN detection or certificate discovery
3. Run CDN detection before real IP discovery
4. Aggregate findings before technology detection and network discovery
5. Vulnerability scanning should be last, after all assets are identified
6. Skip steps only if there's a specific reason (e.g., time constraints)
7. Consider parallelizing independent steps when possible

Output your plan as a JSON object with this structure:
{{
    "target": "<target_domain>",
    "steps": [
        {{"name": "<step_name>", "reason": "<why_this_step>", "priority": <1-5>}}
    ],
    "estimated_time_minutes": <number>,
    "notes": "<any_special_considerations>"
}}

Priority scale: 1=critical, 2=high, 3=medium, 4=low, 5=optional
"""

        user_message = """Analyze this target and create a reconnaissance plan:

Target: {target}
{context}

Generate an optimal reconnaissance plan as JSON."""

        return ChatPromptTemplate.from_messages([
            ("system", system_message),
            ("human", user_message),
        ])
    
    async def create_plan(
        self,
        target: str,
        context: Optional[str] = None,
        custom_steps: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a reconnaissance plan for the target.
        
        Parameters
        ----------
        target : str
            Target domain or IP to analyze
        context : str, optional
            Additional context about engagement scope, constraints, etc.
        custom_steps : List[str], optional
            Custom list of steps to consider (overrides STANDARD_STEPS)
            
        Returns
        -------
        Dict[str, Any]
            Generated plan with steps, priorities, and metadata
        """
        steps_to_use = custom_steps or self.STANDARD_STEPS
        
        prompt_template = self.create_planning_prompt(target, context)
        
        chain = prompt_template | self.llm | self.parser
        
        context_str = f"Context: {context}" if context else ""
        
        try:
            result = await chain.ainvoke({
                "target": target,
                "context": context_str,
            })
            
            if self.verbose:
                print(f"\n📋 Generated Plan for {target}:")
                print(f"   Steps: {len(result.get('steps', []))}")
                print(f"   Estimated Time: {result.get('estimated_time_minutes', 'N/A')} minutes")
            
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Plan generation failed: {e}, using standard workflow")
            
            # Fallback to standard sequential plan
            return {
                "target": target,
                "steps": [
                    {"name": step, "reason": "Standard reconnaissance step", "priority": 3}
                    for step in steps_to_use
                ],
                "estimated_time_minutes": 30,
                "notes": "Standard plan used due to planning error",
            }
    
    def create_execution_prompt(self) -> ChatPromptTemplate:
        """
        Create a prompt template for executing reconnaissance steps.
        
        Returns
        -------
        ChatPromptTemplate
            Prompt template for step execution guidance
        """
        return ChatPromptTemplate.from_messages([
            ("system", """You are an autonomous reconnaissance execution agent.

You have access to tools for each reconnaissance step. Your job is to:
1. Execute the requested step using the appropriate tool
2. Analyze the results thoroughly
3. Identify key findings and patterns
4. Recommend next steps or highlight critical issues

Always think step-by-step and provide clear, actionable insights."""),
            MessagesPlaceholder(variable_name="messages"),
            ("human", "{input}"),
        ])
    
    async def analyze_results(
        self,
        step_name: str,
        results: str,
        previous_findings: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Use LLM to analyze reconnaissance results.
        
        Parameters
        ----------
        step_name : str
            Name of the reconnaissance step
        results : str
            Raw results from the step
        previous_findings : Dict[str, str], optional
            Findings from previous steps for context
            
        Returns
        -------
        Dict[str, Any]
            Analysis including key findings, risk indicators, and recommendations
        """
        analysis_prompt = f"""Analyze these {step_name} results:

{results}

Provide a structured analysis with:
1. Key findings (top 5 most important discoveries)
2. Risk indicators (potential security issues)
3. Patterns observed
4. Recommendations for next steps
5. Critical items requiring immediate attention

Format as JSON with keys: key_findings, risk_indicators, patterns, recommendations, critical_items
"""

        if previous_findings:
            prev_context = "\n\nPrevious findings from other steps:\n"
            for step, finding in previous_findings.items():
                prev_context += f"- {step}: {finding[:200]}...\n"
            analysis_prompt = prev_context + "\n" + analysis_prompt
        
        try:
            messages = [HumanMessage(content=analysis_prompt)]
            response = await self.llm.ainvoke(messages)
            
            # Try to parse as JSON, fallback to text
            try:
                import json
                content = response.content if hasattr(response, 'content') else str(response)
                # Extract JSON from response if present
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "{" in content and "}" in content:
                    start = content.find("{")
                    end = content.rfind("}") + 1
                    content = content[start:end]
                analysis = json.loads(content)
            except:
                analysis = {
                    "summary": response.content if hasattr(response, 'content') else str(response),
                    "raw_analysis": True,
                }
            
            return analysis
            
        except Exception as e:
            return {"error": str(e), "raw_results": results}
    
    def get_step_dependencies(self) -> Dict[str, List[str]]:
        """
        Get dependency graph for reconnaissance steps.
        
        Returns
        -------
        Dict[str, List[str]]
            Mapping of step names to their dependencies
        """
        return {
            "enumerate_subdomains": [],
            "extract_ips": ["enumerate_subdomains"],
            "detect_cdn": ["extract_ips"],
            "discover_certificates": ["extract_ips"],
            "discover_real_ip": ["detect_cdn"],
            "recon_asn": ["extract_ips"],
            "aggregate_findings": [
                "enumerate_subdomains",
                "extract_ips",
                "detect_cdn",
                "discover_certificates",
                "recon_asn",
            ],
            "detect_technologies": ["aggregate_findings"],
            "discover_network": ["aggregate_findings"],
            "scan_vulnerabilities": [
                "aggregate_findings",
                "detect_technologies",
            ],
        }
    
    def validate_plan(self, plan: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a generated plan for correctness.
        
        Parameters
        ----------
        plan : Dict[str, Any]
            Plan to validate
            
        Returns
        -------
        Tuple[bool, List[str]]
            (is_valid, list_of_issues)
        """
        issues = []
        dependencies = self.get_step_dependencies()
        executed_steps = set()
        
        steps = plan.get("steps", [])
        if not steps:
            issues.append("Plan has no steps")
            return False, issues
        
        for i, step in enumerate(steps):
            step_name = step.get("name", "")
            
            # Check if step exists
            if step_name not in self.STANDARD_STEPS:
                issues.append(f"Step {i+1}: Unknown step '{step_name}'")
                continue
            
            # Check dependencies
            required_deps = dependencies.get(step_name, [])
            missing_deps = set(required_deps) - executed_steps
            if missing_deps:
                issues.append(
                    f"Step {i+1} ({step_name}): Missing dependencies: {missing_deps}"
                )
            
            executed_steps.add(step_name)
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    async def generate_summary(
        self,
        target: str,
        all_findings: Dict[str, Any],
    ) -> str:
        """
        Generate an executive summary of all reconnaissance findings.
        
        Parameters
        ----------
        target : str
            Target domain
        all_findings : Dict[str, Any]
            All findings from all steps
            
        Returns
        -------
        str
            Executive summary text
        """
        summary_prompt = f"""Generate an executive summary of reconnaissance findings for {target}.

Findings by category:
"""
        for step, data in all_findings.items():
            if isinstance(data, dict):
                data = str(data.get("summary", data))
            summary_prompt += f"\n## {step}\n{data[:500]}\n"
        
        summary_prompt += """

Create a professional executive summary covering:
1. Overall attack surface size and complexity
2. Most critical security findings
3. Infrastructure patterns observed
4. High-priority remediation recommendations
5. Suggested next steps for deeper assessment

Write for a technical but non-specialist audience (CTO, Security Manager)."""

        try:
            messages = [HumanMessage(content=summary_prompt)]
            response = await self.llm.ainvoke(messages)
            return response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            return f"Summary generation failed: {e}"
