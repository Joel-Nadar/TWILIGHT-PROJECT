"""
Scripted normal workflows for agents.
Used for baselines and demo.
"""
import asyncio
from agents.researcher import ResearcherAgent
from agents.emailer import EmailerAgent
from agents.payments import PaymentsAgent


async def baseline_researcher_workflow():
    """Baseline workflow for researcher agent"""
    print("Running baseline researcher workflow...")
    
    researcher = ResearcherAgent()
    
    # Search web
    result = await researcher.search_web("machine learning")
    print(f"Search result: {result}")
    
    # Fetch webpage
    result = await researcher.fetch_webpage("https://example.com")
    print(f"Fetch result: {result}")
    
    # Send message to emailer
    result = await researcher.send_message("emailer", "Here are the research results")
    print(f"Message result: {result}")


async def baseline_emailer_workflow():
    """Baseline workflow for emailer agent"""
    print("Running baseline emailer workflow...")
    
    emailer = EmailerAgent()
    
    # Send email
    result = await emailer.send_email(
        to="someone@company.com",
        subject="Research Results",
        body="Here are the latest research findings."
    )
    print(f"Email result: {result}")
    
    # Read inbox
    result = await emailer.read_inbox(limit=5)
    print(f"Inbox result: {result}")
    
    # Send message to researcher
    result = await emailer.send_message("researcher", "Email sent successfully")
    print(f"Message result: {result}")


async def baseline_payments_workflow():
    """Baseline workflow for payments agent"""
    print("Running baseline payments workflow...")
    
    payments = PaymentsAgent()
    
    # Make payment
    result = await payments.make_payment(
        to_account="ACC-12345",
        amount=100.0,
        memo="Invoice payment"
    )
    print(f"Payment result: {result}")
    
    # Send message to emailer
    result = await payments.send_message("emailer", "Payment completed")
    print(f"Message result: {result}")


async def run_all_baselines():
    """Run all baseline workflows"""
    print("=" * 50)
    print("Running all baseline workflows")
    print("=" * 50)
    
    await baseline_researcher_workflow()
    print()
    
    await baseline_emailer_workflow()
    print()
    
    await baseline_payments_workflow()
    print()
    
    print("=" * 50)
    print("All baselines complete")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(run_all_baselines())
