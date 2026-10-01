"""
Emailer agent - sends emails and reads inboxes.
"""
from agents.base_agent import BaseAgent


class EmailerAgent(BaseAgent):
    """Emailer agent implementation"""
    
    def __init__(self):
        super().__init__("emailer")
    
    async def send_email(self, to: str, subject: str, body: str):
        """Send an email"""
        return await self.call_tool("send_email", {"to": to, "subject": subject, "body": body})
    
    async def read_inbox(self, limit: int = 10):
        """Read inbox"""
        return await self.call_tool("read_inbox", {"limit": limit})
    
    async def send_message(self, to_agent: str, content: str):
        """Send a message to another agent"""
        return await self.call_tool("send_message", {"to_agent": to_agent, "content": content})
