"""
Base agent classes for RA137 reconnaissance system.

Provides:
- AgentState: Typed state container for agent execution
- ReconAgent: Base class for all reconnaissance agents
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from enum import Enum


class AgentStatus(Enum):
    """Agent execution status."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentState:
    """
    Typed state container for agent execution.
    
    Attributes
    ----------
    target : str
        Target domain or IP being analyzed
    current_step : str
        Current reconnaissance step being executed
    completed_steps : List[str]
        List of successfully completed steps
    failed_steps : List[str]
        List of failed steps
    findings : Dict[str, Any]
        Accumulated findings from all modules
    messages : List[Dict[str, str]]
        Conversation history for LLM interactions
    metadata : Dict[str, Any]
        Additional metadata (timestamps, config, etc.)
    status : AgentStatus
        Current agent execution status
    error_message : Optional[str]
        Error message if status is FAILED
    """
    target: str = ""
    current_step: str = ""
    completed_steps: List[str] = field(default_factory=list)
    failed_steps: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    messages: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: AgentStatus = AgentStatus.IDLE
    error_message: Optional[str] = None
    
    def add_finding(self, module: str, data: Any) -> None:
        """Add a finding to the state."""
        self.findings[module] = data
    
    def add_message(self, role: str, content: str) -> None:
        """Add a message to the conversation history."""
        self.messages.append({"role": role, "content": content})
    
    def mark_step_complete(self, step: str) -> None:
        """Mark a step as completed."""
        if step not in self.completed_steps:
            self.completed_steps.append(step)
    
    def mark_step_failed(self, step: str, error: str) -> None:
        """Mark a step as failed."""
        if step not in self.failed_steps:
            self.failed_steps.append(step)
        self.error_message = error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary."""
        return {
            "target": self.target,
            "current_step": self.current_step,
            "completed_steps": self.completed_steps,
            "failed_steps": self.failed_steps,
            "findings": self.findings,
            "messages": self.messages,
            "metadata": self.metadata,
            "status": self.status.value,
            "error_message": self.error_message,
        }


class ReconAgent:
    """
    Base class for all reconnaissance agents.
    
    Provides common functionality for:
    - State management
    - Tool registration and execution
    - LLM interaction
    - Async execution support
    
    Subclasses should override:
    - _execute(): Main execution logic
    - get_system_prompt(): Agent-specific system prompt
    """
    
    def __init__(
        self,
        name: str = "ReconAgent",
        description: str = "Autonomous reconnaissance agent",
        llm: Optional[Any] = None,
        tools: Optional[List[Any]] = None,
    ):
        """
        Initialize the reconnaissance agent.
        
        Parameters
        ----------
        name : str
            Agent name for identification
        description : str
            Human-readable description of agent capabilities
        llm : Any, optional
            LangChain LLM instance (default: auto-created from config)
        tools : List[Any], optional
            List of LangChain Tool instances
        """
        self.name = name
        self.description = description
        self.state = AgentState()
        self._tools = tools or []
        self._llm = llm
        self._status = AgentStatus.IDLE
        
        # Lazy LLM initialization
        if self._llm is None:
            self._llm = self._create_llm()
    
    def _create_llm(self) -> Any:
        """
        Create an LLM instance from configuration.
        
        Returns
        -------
        Any
            LangChain LLM instance (ChatOpenAI or ChatOllama)
        """
        try:
            from utils.config import get_config
            config = get_config()
            
            if config.ai.provider.lower() == "ollama":
                from langchain_ollama import ChatOllama
                return ChatOllama(
                    model=config.ai.model or "llama3",
                    base_url=config.ai.base_url or "http://localhost:11434",
                    temperature=0.1,
                )
            else:
                from langchain_openai import ChatOpenAI
                kwargs = {
                    "model": config.ai.model or "gpt-4o-mini",
                    "temperature": 0.1,
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
    
    @property
    def tools(self) -> List[Any]:
        """Get registered tools."""
        return self._tools
    
    @tools.setter
    def tools(self, value: List[Any]) -> None:
        """Set registered tools."""
        self._tools = value
    
    def add_tool(self, tool: Any) -> None:
        """Add a tool to the agent."""
        self._tools.append(tool)
    
    def get_system_prompt(self) -> str:
        """
        Get the system prompt for this agent.
        
        Subclasses should override to provide agent-specific instructions.
        
        Returns
        -------
        str
            System prompt text
        """
        return f"""You are {self.name}, an autonomous reconnaissance agent.

{self.description}

Your task is to systematically analyze the target using available tools,
gather intelligence, and provide actionable security insights.

Always:
1. Think step-by-step before taking actions
2. Analyze results thoroughly before proceeding
3. Document findings clearly
4. Prioritize high-value targets and critical findings
5. Respect rate limits and ethical boundaries

Current target: {{target}}
"""
    
    async def execute(
        self,
        target: str,
        output_dir: Optional[Path] = None,
        **kwargs: Any,
    ) -> AgentState:
        """
        Execute the agent asynchronously.
        
        Parameters
        ----------
        target : str
            Target domain or IP to analyze
        output_dir : Path, optional
            Output directory for results
        **kwargs : Any
            Additional parameters
            
        Returns
        -------
        AgentState
            Final agent state after execution
        """
        self.state = AgentState(target=target)
        self.state.status = AgentStatus.RUNNING
        self.state.metadata["output_dir"] = str(output_dir) if output_dir else None
        self.state.metadata.update(kwargs)
        
        try:
            result = await self._execute(target, output_dir, **kwargs)
            self.state.status = AgentStatus.COMPLETED
            return self.state
        except Exception as e:
            self.state.status = AgentStatus.FAILED
            self.state.error_message = str(e)
            raise
    
    def execute_sync(
        self,
        target: str,
        output_dir: Optional[Path] = None,
        **kwargs: Any,
    ) -> AgentState:
        """
        Execute the agent synchronously.
        
        Convenience wrapper around execute() for synchronous contexts.
        """
        return asyncio.run(self.execute(target, output_dir, **kwargs))
    
    async def _execute(
        self,
        target: str,
        output_dir: Optional[Path],
        **kwargs: Any,
    ) -> AgentState:
        """
        Main execution logic - must be implemented by subclasses.
        
        Parameters
        ----------
        target : str
            Target domain or IP
        output_dir : Path, optional
            Output directory
        **kwargs : Any
            Additional parameters
            
        Returns
        -------
        AgentState
            Updated agent state
        """
        raise NotImplementedError("Subclasses must implement _execute()")
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, status={self._status.value})"
