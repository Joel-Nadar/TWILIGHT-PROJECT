"""
Payments agent - makes payments and sends messages.
"""
from agents.base_agent import BaseAgent


class PaymentsAgent(BaseAgent):
    """Payments agent implementation"""
    
    def __init__(self):
        super().__init__("payments")
    
    async def make_payment(self, to_account: str, amount: float, memo: str):
        """Make a payment"""
        return await self.call_tool("make_payment", {
            "to_account": to_account,
            "amount": amount,
            "memo": memo
        })
    
    async def send_message(self, to_agent: str, content: str):
        """Send a message to another agent"""
        return await self.call_tool("send_message", {"to_agent": to_agent, "content": content})
