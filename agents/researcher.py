"""
Researcher agent - searches web and fetches webpages.
"""
from agents.base_agent import BaseAgent


class ResearcherAgent(BaseAgent):
    """Researcher agent implementation"""
    
    def __init__(self):
        super().__init__("researcher")
    
    async def search_web(self, query: str):
        """Search the web"""
        return await self.call_tool("search_web", {"query": query})
    
    async def fetch_webpage(self, url: str):
        """Fetch a webpage"""
        return await self.call_tool("fetch_webpage", {"url": url})
    
    async def send_message(self, to_agent: str, content: str):
        """Send a message to another agent"""
        return await self.call_tool("send_message", {"to_agent": to_agent, "content": content})
