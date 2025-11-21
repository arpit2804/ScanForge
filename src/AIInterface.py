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
        
    async def generate_payloads(self, vulnerability_type: str, context: Dict[str, Any], count: int = 10) -> List[str]:
            """
            AI-powered payload generation - completely dynamic and context-aware.
            No hardcoded templates, pure intelligence.
            """
            system_prompt = """You are an expert penetration testing payload generator.

        Your role:
        - Generate realistic, diverse payloads for security testing
        - Adapt payloads based on context (parameter names, types, application framework, etc.)
        - Be creative - don't just use templates
        - Consider WAF bypasses, encoding variations, and real-world attack vectors

        Output Format:
        Return ONLY a JSON object with a "payloads" array.
        {"payloads": ["payload1", "payload2", ...]}

        Examples of context-aware thinking:
        - If testing a "username" parameter → try authentication bypass payloads
        - If testing an "email" field → consider email-specific injection vectors
        - If the app uses Node.js → consider prototype pollution
        - If you see a file upload → consider extension bypasses

        Be intelligent and adaptive, not template-based."""

            context_description = self._describe_context(context) if context else "No specific context provided"
            
            user_prompt = f"""Generate {count} payloads for testing {vulnerability_type.upper()} vulnerability.

        Context Information:
        {context_description}

        Think step-by-step:
        1. What is the target system likely using?
        2. What injection points are available?
        3. What payloads would be most effective?
        4. What variations or bypasses should I try?

        Generate {count} intelligent, context-aware payloads."""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

            try:
                response_str = await self._call_llm(messages, max_tokens=3000, is_json=True)
                data = json.loads(response_str)
                
                if isinstance(data, dict) and 'payloads' in data:
                    payloads = data['payloads']
                elif isinstance(data, list):
                    payloads = data
                else:
                    logger.warning(f"Unexpected AI response format: {data}")
                    return []
                
                logger.info(f"AI generated {len(payloads)} payloads for {vulnerability_type}")
                return payloads[:count]
                
            except Exception as e:
                logger.error(f"AI payload generation failed: {e}")
                return []

    def _describe_context(self, context: Dict[str, Any]) -> str:
        """Convert context dict into natural language for the LLM"""
        if not context:
            return "No context provided"
        
        description_parts = []
        
        if 'url' in context:
            description_parts.append(f"Target URL: {context['url']}")
        
        if 'parameters' in context:
            params = context['parameters']
            if isinstance(params, list):
                description_parts.append(f"Parameters: {', '.join(params)}")
            elif isinstance(params, dict):
                description_parts.append(f"Parameters: {json.dumps(params)}")
        
        if 'method' in context:
            description_parts.append(f"HTTP Method: {context['method']}")
        
        if 'inputs' in context:
            inputs = context['inputs']
            if isinstance(inputs, list):
                input_names = [inp.get('name', 'unknown') for inp in inputs]
                description_parts.append(f"Form inputs: {', '.join(input_names)}")
        
        if 'framework' in context:
            description_parts.append(f"Detected framework: {context['framework']}")
        
        if 'headers' in context:
            description_parts.append(f"Response headers indicate: {context['headers']}")
        
        # Add any other fields as raw JSON
        other_fields = {k: v for k, v in context.items() 
                    if k not in ['url', 'parameters', 'method', 'inputs', 'framework', 'headers']}
        if other_fields:
            description_parts.append(f"Additional context: {json.dumps(other_fields)}")
        
        return "\n".join(description_parts)

    async def analyze_response_with_ai(self, request: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered response analysis - no regex patterns, pure intelligence.
        The AI understands context and makes intelligent judgments.
        """
        system_prompt = """You are an expert security analyst specializing in vulnerability detection.
    Your role:
    - Analyze HTTP responses for signs of security vulnerabilities
    - Consider the context of the request and payload used
    - Look for both obvious and subtle indicators
    - Provide confidence scores and reasoning

    Analysis Guidelines:
    1. Check if payloads are reflected (and how)
    2. Look for error messages that leak information
    3. Consider timing anomalies (blind vulnerabilities)
    4. Check for behavioral changes

    Output Format:
    Return a JSON object with your analysis.
    {
    "vulnerability_detected": true/false,
    "vulnerability_type": "xss/sqli/ssrf/etc or null",
    "confidence": 0.0-1.0,
    "indicators": {
        "payload_reflected": true/false,
        "error_messages": ["list of errors found"],
        "suspicious_patterns": ["patterns that indicate vulnerability"],
        "behavioral_anomalies": ["unusual behaviors"]
    },
    "reasoning": "Explain your analysis",
    "recommendations": ["next steps for confirmation"]
    }"""

        # Prepare context for AI
        payload = request.get('payload', '')
        vulnerability_type = request.get('vulnerability_type', 'unknown')
        
        response_body = response.get('body', '')
        # Truncate large responses but keep key parts
        if len(response_body) > 6000:
            response_body_sample = response_body[:3000] + "\n...[truncated]...\n" + response_body[-3000:]
        else:
            response_body_sample = response_body
        
        user_prompt = f"""Analyze this HTTP response for vulnerability indicators.

    Request Context:
    - Payload sent: {payload}
    - Testing for: {vulnerability_type}
    - Target URL: {request.get('url', 'unknown')}
    - HTTP Method: {request.get('method', 'GET')}

    Response Data:
    - Status Code: {response.get('status_code', 'unknown')}
    - Response Time: {response.get('response_time', 0):.3f} seconds
    - Response Headers: {json.dumps(response.get('headers', {}), indent=2)}

    Response Body (sample):
    {response_body_sample}

    Analyze this response carefully and provide your expert assessment."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        try:
            response_str = await self._call_llm(messages, max_tokens=2000, is_json=True)
            analysis = json.loads(response_str)
            
            logger.info(f"AI Analysis: {analysis.get('vulnerability_type', 'none')} "
                    f"(confidence: {analysis.get('confidence', 0):.2f})")
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI response analysis failed: {e}")
            return {
                "vulnerability_detected": False,
                "confidence": 0.0,
                "error": str(e),
                "reasoning": "AI analysis failed, falling back to basic checks"
            }


    def _get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        Tool definitions that emphasize AI-powered intelligence.
        """
        return [
            {
                "name": "crawl_site",
                "description": "Crawls a website to discover endpoints, forms, and attack surface.",
                "parameters": {
                    "seed_url": "str (required)",
                    "depth": "int (optional, default 2, max 3)",
                    "scope_domains": "list[str] (optional)"
                }
            },
            {
                "name": "get_payloads",
                "description": """AI-powered payload generator. Can generate payloads for ANY vulnerability type.
                
    The AI understands context and generates intelligent, adaptive payloads. You can request payloads for:
    - Standard types: xss, sqli, ssrf, lfi, rfi, rce, xxe, idor, csrf
    - Advanced types: ssti, nosql, ldap, xpath, crlf, host_header, prototype_pollution
    - Any other type: Just specify the vulnerability name and the AI will generate appropriate payloads

    The more context you provide, the better the payloads. Context can include:
    - Target URL and parameters
    - Application framework or technology
    - Parameter names and types
    - Previous response information""",
                "parameters": {
                    "vulnerability_type": "str (required, any vulnerability type name)",
                    "context": "dict (optional but recommended, provide target details)",
                    "count": "int (optional, default 10, max 50)"
                }
            },
            {
                "name": "inject_payload",
                "description": "Sends a request to a target with a specific payload in the specified injection point.",
                "parameters": {
                    "url": "str (required)",
                    "injection_point": "dict (required, e.g., {'type': 'query_param', 'name': 'id'})",
                    "payload": "str (required)",
                    "method": "str (optional, default 'GET')"
                }
            },
            {
                "name": "analyze_response",
                "description": """AI-powered response analyzer. Intelligently detects vulnerability indicators.

    Instead of regex patterns, this uses AI to:
    - Understand context and identify subtle indicators
    - Detect various vulnerability types dynamically
    - Provide confidence scores and reasoning
    - Suggest next steps for confirmation

    The AI considers:
    - Payload reflection and encoding
    - Error messages and information disclosure
    - Timing anomalies (blind vulnerabilities)
    - Behavioral changes and anomalies
    - Response patterns specific to the vulnerability type tested""",
                "parameters": {
                    "request": "dict (required, info about the request sent)",
                    "response": "dict (required, the HTTP response to analyze)"
                }
            },
            {
                "name": "save_finding",
                "description": "Saves a confirmed vulnerability to the database.",
                "parameters": {
                    "vulnerability": "dict (required, full vulnerability data)"
                }
            },
            {
                "name": "validate_target",
                "description": "Validates if a URL is within the allowed testing scope.",
                "parameters": {
                    "url": "str (required)",
                    "scope_rules": "dict (optional)"
                }
            }
        ]


    async def decide_next_step(self, goal: str, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        The core "brain" of the agent. Decides the next tool to call, or provides a final answer.
        """
        system_prompt = f"""
You are ScanForge, an expert AI vulnerability scanning agent with AI-powered tools.

## Your Capabilities:
1. **AI-Powered Payload Generation**: 
   - Call get_payloads with ANY vulnerability type - not limited to predefined types
   - The payload generator uses AI to create context-aware, intelligent payloads
   - Provide context (URL, parameters, framework) for better payloads

2. **AI-Powered Response Analysis**:
   - Call analyze_response to get intelligent vulnerability detection
   - No regex patterns - pure AI understanding
   - Receives confidence scores, reasoning, and recommendations
   - Can detect subtle indicators that rules-based systems miss

3. **Traditional Tools**:
   - crawl_site: Discover attack surface
   - inject_payload: Test endpoints
   - validate_target: Check scope
   - save_finding: Store results

## Intelligence Philosophy:
- You have AI-powered tools, not template-based tools
- Be creative in your testing approach
- The tools adapt to context - provide good context for better results
- Trust the AI analysis but verify with multiple tests if confidence is low

## Available Tools:
{json.dumps(self._get_tool_definitions(), indent=2)}

## Response Format:
You MUST respond with a single valid JSON object with 'thought' and either 'tool_name' or 'final_answer'.

Example with context:
{{
  "thought": "I'll generate context-aware XSS payloads for this email field",
  "tool_name": "get_payloads",
  "params": {{
    "vulnerability_type": "xss",
    "count": 8,
    "context": {{
      "url": "https://example.com/profile",
      "parameters": ["email", "name"],
      "input_type": "email",
      "framework": "React"
    }}
  }}
}}

Example analysis:
{{
  "thought": "Let me analyze this response using AI",
  "tool_name": "analyze_response",
  "params": {{
    "request": {{"payload": "<script>alert(1)</script>", "url": "...", "vulnerability_type": "xss"}},
    "response": {{"status_code": 200, "body": "...", "headers": {{...}}}}
  }}
}}

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
