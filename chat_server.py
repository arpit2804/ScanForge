import asyncio
import aiohttp
import uvicorn
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional
import time
import uuid

from src.AIInterface import AIInterface
from src.main import VulnScanAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str
    status: str

# Global instances
chat_sessions = {}
agent_instances = {}
MCP_SERVER_URL = "http://127.0.0.1:8000"

class ChatSession:
    """Manages a single chat session with context memory"""
    def __init__(self, session_id: str, ai_interface: AIInterface, max_context_messages: int = 10):
        self.session_id = session_id
        self.ai_interface = ai_interface
        self.conversation_history = []
        self.agent_history = []  # For the VulnScanAgent
        self.max_context_messages = max_context_messages
        self.last_activity = time.time()
        self.agent = None
        
    async def initialize_agent(self):
        """Initialize the VulnScanAgent for this session"""
        self.agent = VulnScanAgent(MCP_SERVER_URL, self.ai_interface)
        await self.agent.__aenter__()
        
    async def cleanup(self):
        """Cleanup agent resources"""
        if self.agent:
            await self.agent.__aexit__(None, None, None)
            
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
        
    def add_message(self, role: str, content: str):
        """Add a message to conversation history"""
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": time.time()
        })
        # Keep only last N messages for context
        if len(self.conversation_history) > self.max_context_messages * 2:
            self.conversation_history = self.conversation_history[-(self.max_context_messages * 2):]
    
    async def process_message(self, user_message: str) -> str:
        """Process a user message and return agent response"""
        self.update_activity()
        self.add_message("user", user_message)
        
        try:
            # Use the agent's history for tool execution context
            next_step = await self.ai_interface.decide_next_step(user_message, self.agent_history)
            
            response_parts = []
            
            # Handle the agent's decision
            if "final_answer" in next_step:
                response = next_step["final_answer"]
                self.add_message("assistant", response)
                return response
            
            # Execute tool calls until we get a final answer or hit max iterations
            max_iterations = 100
            iteration = 0
            
            while iteration < max_iterations:
                if "tool_name" in next_step:
                    tool_name = next_step["tool_name"]
                    params = next_step["params"]
                    thought = next_step.get("thought", "")
                    
                    if thought:
                        response_parts.append(f"💭 {thought}")
                    
                    response_parts.append(f"🔧 Using tool: {tool_name}")
                    
                    # Execute the tool
                    tool_result = await self.agent._call_mcp_tool(tool_name, params)
                    
                    # Truncate result for history
                    result_for_history = self.agent._truncate_result(tool_result)
                    
                    # Add to agent history
                    self.agent_history.append({
                        "action": next_step,
                        "result": result_for_history
                    })
                    
                    # Keep agent history manageable
                    if len(self.agent_history) > 15:
                        self.agent_history = self.agent_history[-15:]
                    
                    # Get next step
                    next_step = await self.ai_interface.decide_next_step(user_message, self.agent_history)
                    
                    if "final_answer" in next_step:
                        response_parts.append(f"\n✅ {next_step['final_answer']}")
                        break
                        
                    iteration += 1
                else:
                    response_parts.append("❌ Unable to determine next action")
                    break
            
            if iteration >= max_iterations:
                response_parts.append("\n⚠️ Reached maximum iterations. Task may be incomplete.")
            
            final_response = "\n".join(response_parts)
            self.add_message("assistant", final_response)
            return final_response
            
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            error_msg = f"❌ Error: {str(e)}"
            self.add_message("assistant", error_msg)
            return error_msg

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown"""
    logger.info("Starting chat server...")
    yield
    
    # Cleanup all sessions
    logger.info("Shutting down chat server...")
    for session in agent_instances.values():
        await session.cleanup()

app = FastAPI(lifespan=lifespan)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def cleanup_old_sessions():
    """Remove sessions inactive for more than 30 minutes"""
    current_time = time.time()
    timeout = 1800  # 30 minutes
    
    sessions_to_remove = []
    for session_id, session in chat_sessions.items():
        if current_time - session.last_activity > timeout:
            sessions_to_remove.append(session_id)
    
    for session_id in sessions_to_remove:
        logger.info(f"Cleaning up inactive session: {session_id}")
        session = chat_sessions.pop(session_id)
        await session.cleanup()
        agent_instances.pop(session_id, None)

@app.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    """Main chat endpoint"""
    await cleanup_old_sessions()
    
    # Get or create session
    session_id = message.session_id or str(uuid.uuid4())
    
    if session_id not in chat_sessions:
        logger.info(f"Creating new chat session: {session_id}")
        ai_interface = AIInterface()
        session = ChatSession(session_id, ai_interface)
        await session.initialize_agent()
        chat_sessions[session_id] = session
        agent_instances[session_id] = session
    else:
        session = chat_sessions[session_id]
    
    try:
        response = await session.process_message(message.message)
        return ChatResponse(
            response=response,
            session_id=session_id,
            status="success"
        )
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/new_session")
async def new_session():
    """Create a new chat session"""
    session_id = str(uuid.uuid4())
    return {"session_id": session_id, "status": "created"}

@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a chat session"""
    if session_id in chat_sessions:
        session = chat_sessions.pop(session_id)
        await session.cleanup()
        agent_instances.pop(session_id, None)
        return {"status": "deleted", "session_id": session_id}
    return {"status": "not_found", "session_id": session_id}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_sessions": len(chat_sessions),
        "mcp_server": MCP_SERVER_URL
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)