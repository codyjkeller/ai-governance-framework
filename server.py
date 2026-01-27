import uvicorn
import uuid
import os
import httpx
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional

# Import your existing modules
from guardrails.governance_guardrail import GovernanceProxy
from guardrails.output_scanner import OutputGuard
from audit_logger import AuditLogger

# --- CONFIGURATION ---
# Load secrets from Environment Variables (Best Practice for DevSecOps)
UPSTREAM_LLM_URL = os.getenv("LLM_API_URL", "https://api.openai.com/v1/chat/completions")
UPSTREAM_API_KEY = os.getenv("LLM_API_KEY", "sk-proj-...") 
JIRA_WEBHOOK_URL = os.getenv("JIRA_WEBHOOK", "") # The webhook URL created in Jira

# Initialize App & Governance Engine
app = FastAPI(title="AI Governance Proxy", version="2.1")
input_guard = GovernanceProxy()
output_guard = OutputGuard()
auditor = AuditLogger()

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    user_id: Optional[str] = "anonymous"
    temperature: Optional[float] = 0.7

async def notify_jira(transaction_id: str, user_id: str, violations: str):
    """Background task to fire a Jira ticket on policy blocks."""
    if not JIRA_WEBHOOK_URL:
        return
        
    payload = {
        "summary": f"Security Alert: AI Policy Violation by {user_id}",
        "description": f"Blocked Transaction: {transaction_id}\nViolations: {violations}\nAction: Immediate Investigation required.",
        "issuetype": "Incident",
        "priority": "High"
    }
    async with httpx.AsyncClient() as client:
        try:
            await client.post(JIRA_WEBHOOK_URL, json=payload)
        except Exception as e:
            print(f"Failed to trigger Jira: {e}")

@app.post("/v1/chat/completions")
async def proxy_chat_completion(request: ChatRequest, background_tasks: BackgroundTasks):
    transaction_id = str(uuid.uuid4())
    user_prompt = request.messages[-1].content
    
    # --- LAYER 1: INPUT SCAN ---
    sanitized_prompt, status = input_guard.scan_prompt(user_prompt)
    
    if status == "BLOCKED":
        # Log the block locally
        auditor.log_event(
            event_type="INPUT_SCAN",
            prompt_id=transaction_id,
            status="BLOCKED",
            details="Critical Data Detected",
            user_id=request.user_id
        )
        # Trigger Jira Automation (Async so it doesn't slow down the user)
        background_tasks.add_task(notify_jira, transaction_id, request.user_id, "Critical PII/Secrets in Prompt")
        
        raise HTTPException(status_code=403, detail="Prompt blocked by AI Acceptable Use Policy.")
    
    # Update the prompt in the request payload if redaction happened
    if sanitized_prompt != user_prompt:
        request.messages[-1].content = sanitized_prompt
        auditor.log_event("INPUT_SCAN", transaction_id, "REDACTED", "PII Masked", request.user_id)

    # --- LAYER 2: UPSTREAM MODEL CALL (Real Traffic) ---
    headers = {
        "Authorization": f"Bearer {UPSTREAM_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Forward the sanitized request to OpenAI/Azure
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            upstream_response = await client.post(
                UPSTREAM_LLM_URL, 
                json=request.dict(), 
                headers=headers
            )
            upstream_response.raise_for_status()
            response_data = upstream_response.json()
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"Upstream Provider Error: {str(e)}")
    
    raw_llm_response = response_data['choices'][0]['message']['content']
    
    # --- LAYER 3: OUTPUT SCAN ---
    safe_response, out_status = output_guard.scan_completion(raw_llm_response)
    
    if out_status == "BLOCKED":
        auditor.log_event("OUTPUT_SCAN", transaction_id, "BLOCKED", "Data Leakage Detected", request.user_id)
        # Trigger Jira for Data Leakage
        background_tasks.add_task(notify_jira, transaction_id, request.user_id, "Potential Data Exfiltration in Output")
        
        raise HTTPException(status_code=502, detail="Response suppressed due to Data Leakage Policy.")

    # Success Log
    auditor.log_event("TRANSACTION_COMPLETE", transaction_id, "SUCCESS", "Request fulfilled", request.user_id)
    
    # Update the response content before returning
    response_data['choices'][0]['message']['content'] = safe_response
    return response_data

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
