# ScanForge

MCP-Based AI Vulnerability Scanner Implementation

This implementation provides a complete vulnerability scanning system using
Model Context Protocol (MCP) to separate AI reasoning from scanning execution.

Architecture:
- MCP Server: Handles scanning operations, safety controls, and data persistence
- LLM Agent: Orchestrates scans using reasoning and planning
- Safety Layer: Prevents dangerous operations and ensures scope compliance