import asyncio
import aiohttp
import uvicorn
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
from typing import Dict, Any

# Import your existing classes
from src.AIInterface import AIInterface
from src.main import MCPServer , SecurityError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the request body model for the tool call
class ToolCallRequest(BaseModel):
    tool_name: str
    params: Dict[str, Any]

# Global instances that will be managed by the lifespan manager
server_instances = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown of the MCPServer."""
    print("Starting up...")
    ai_interface = AIInterface()
    mcp_server = MCPServer(ai_interface)
    
    # Manually enter the async context of the mcp_server
    # This calls its __aenter__ method, creating the aiohttp.ClientSession
    await mcp_server.__aenter__()
    
    server_instances['mcp_server'] = mcp_server
    yield
    
    # On shutdown, call the __aexit__ method to clean up
    print("Shutting down...")
    await mcp_server.__aexit__(None, None, None)

app = FastAPI(lifespan=lifespan)

@app.post("/call_tool")
async def handle_tool_call(request: ToolCallRequest):
    """
    Main endpoint for the LLM Agent to call any tool
    on the MCP Server.
    """
    mcp_server = server_instances.get('mcp_server')
    if not mcp_server:
        raise HTTPException(status_code=503, detail="Server not initialized")

    tool_name = request.tool_name
    params = request.params
    
    logger.info(f"Received tool call: {tool_name} with params: {params}")

    try:
        # Use the existing call_tool method from your MCPServer
        result = await mcp_server.call_tool(tool_name, params)
        return result
    except ValueError as e:
        # Handle "Unknown tool"
        raise HTTPException(status_code=400, detail=str(e))
    except SecurityError as e:
        # Handle scope violations
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Error executing tool {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Note: This file should be run with uvicorn for production
    # uvicorn mcp_server_app:app --host 0.0.0.0 --port 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)