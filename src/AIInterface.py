import asyncio
import json
import logging
import re
from typing import Dict, Any, List
from groq import Groq, APIError
from src.config import GROQ_API_KEY, GROQ_MODEL

# Configure logging
logger = logging.getLogger(__name__)

class AIInterface:
    """Interface for the Groq LLM, acting as the agent's 'brain'."""

    def __init__(self):
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY environment variable not set.")
        self.client = Groq(api_key=GROQ_API_KEY)
        self.model = GROQ_MODEL

    async def _call_llm(self, messages: List[Dict[str, str]], max_tokens: int = 2000, is_json: bool = False) -> str:
        """Generic method to call the Groq Chat Completions API."""
        try:
            response_format = {"type": "json_object"} if is_json else None
            
            def sync_call():
                return self.client.chat.completions.create(
                    messages=messages,
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=0.2, # Lower temperature for more deterministic tool use
                    response_format=response_format
                )
            chat_completion = await asyncio.to_thread(sync_call)
            return chat_completion.choices[0].message.content
        except APIError as e:
            logger.error(f"Groq API Error: {e}")
            raise

    def _get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        Returns the list of tools the AI agent can use.
        These match the tools in MCPServer.
        """
        return [
            {
                "name": "crawl_site",
                "description": "Crawls a website to discover endpoints and forms.",
                "parameters": {
                    "seed_url": "str (required)",
                    "depth": "int (optional, default 2)",
                    "scope_domains": "list[str] (optional, default [seed_url_domain])"
                }
            },
            {
                "name": "get_payloads",
                "description": "Generates context-aware payloads for a specific vulnerability type.",
                "parameters": {
                    "vulnerability_type": "str (required, e.g., 'xss', 'sqli')",
                    "context": "dict (optional, details about the target)",
                    "count": "int (optional, default 5)"
                }
            },
            {
                "name": "inject_payload",
                "description": "Sends a request to a target with a specific payload.",
                "parameters": {
                    "url": "str (required)",
                    "injection_point": "dict (required, e.g., {'type': 'query_param', 'name': 'id'})",
                    "payload": "str (required)",
                    "method": "str (optional, default 'GET')"
                }
            },
            {
                "name": "analyze_response",
                "description": "Performs basic analysis on an HTTP response to find indicators.",
                "parameters": {
                    "request": "dict (required, info about the request)",
                    "response": "dict (required, the response to analyze)"
                }
            },
            {
                "name": "save_finding",
                "description": "Saves a confirmed vulnerability to the database.",
                "parameters": {
                    "vulnerability": "dict (required, full vuln data: type, severity, title, etc.)"
                }
            },
            {
                "name": "validate_target",
                "description": "Validates if a URL is within the allowed scope.",
                "parameters": {
                    "url": "str (required)",
                    "scope_rules": "dict (optional, e.g., {'allowed_domains': ['example.com']})"
                }
            }
        ]

    async def decide_next_step(self, goal: str, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        The core "brain" of the agent. Decides the next tool to call, or provides a final answer.
        """
        system_prompt = f"""
You are ScanForge, an expert AI vulnerability scanning agent.
Your goal is to assist the user in their security testing.

You have access to a set of tools. You must reason, step-by-step, to achieve the user's goal.
Base your decisions on the conversation history. Do not repeat steps unless necessary.

## Available Tools:
{json.dumps(self._get_tool_definitions(), indent=2)}

## Response Format:
You MUST respond with a single valid JSON object.
The JSON object MUST include a 'thought' key and EITHER a 'tool_name' or 'final_answer' key.

- To call a tool:
  {{"thought": "I need to crawl the site to find targets.", "tool_name": "crawl_site", "params": {{"seed_url": "https://example.com"}}}}
- When the goal is complete or you need to report:
  {{"thought": "I have found 2 XSS vulnerabilities and the scan is complete. I will now report this to the user.", "final_answer": "Scan complete. Found 2 XSS vulnerabilities at ..."}}

Do not add any text before or after the JSON.
"""

        # Build the message history
        messages = [{"role": "system", "content": system_prompt}]
        messages.append({"role": "user", "content": f"My goal is: {goal}"})

        # Add the agent's action/result history
        for item in history:
            messages.append({"role": "assistant", "content": json.dumps(item["action"])})
            messages.append({"role": "user", "content": f"Tool Result: {json.dumps(item['result'])}"})
        
        # Add a final prompt to force the agent to act
        messages.append({
            "role": "user",
            "content": f"Based on the history, and remembering your main goal is: '{goal}', what is your next step?"
        })

        try:
            response_str = await self._call_llm(messages, max_tokens=2048, is_json=True)
            decision = json.loads(response_str)
            return decision
        except (json.JSONDecodeError, APIError) as e:
            logger.error(f"Failed to get next step from LLM: {e}")
            return {"final_answer": f"Error in agent reasoning: {e}"}
        except Exception as e:
            logger.error(f"Unexpected error in decide_next_step: {e}")
            return {"final_answer": f"An unexpected error occurred: {e}"}