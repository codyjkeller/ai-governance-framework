import uvicorn
import uuid
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional

# Import your existing modules
from guardrails.governance_guardrail import GovernanceProxy
from guardrails.output_scanner import OutputGuard
from audit_logger import AuditLogger

# Initialize App & Governance Engine
app = FastAPI(title="AI Governance Proxy", version="2.0")
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

@app.post("/v1/chat/completions")
async def proxy_chat_completion(request: ChatRequest):
    transaction_id = str(uuid.uuid4())
    user_prompt = request.messages[-1].content  # Grab the last user message
    
    # --- LAYER 1: INPUT SCAN ---
    sanitized_prompt, status = input_guard.scan_prompt(user_prompt)
    
    if status == "BLOCKED":
        # Log the block
        auditor.log_event(
            event_type="INPUT_SCAN",
            prompt_id=transaction_id,
            status="BLOCKED",
            details="Critical Data Detected (See local logs)",
            user_id=request.user_id
        )
        raise HTTPException(status_code=403, detail="Prompt blocked by AI Acceptable Use Policy.")
    
    # Log the sanitization if it happened
    if sanitized_prompt != user_prompt:
        auditor.log_event("INPUT_SCAN", transaction_id, "REDACTED", "PII Masked", request.user_id)

    # --- LAYER 2: MODEL CALL (Mocked for now) ---
    # In a real proxy, here uses `httpx` to forward `sanitized_prompt` to OpenAI
    # response = await call_openai(sanitized_prompt)
    
    # Simulating a response for the demo
    mock_llm_response = f"I processed your request regarding: {sanitized_prompt[:20]}..."
    
    # --- LAYER 3: OUTPUT SCAN ---
    safe_response, out_status = output_guard.scan_completion(mock_llm_response)
    
    if out_status == "BLOCKED":
        auditor.log_event("OUTPUT_SCAN", transaction_id, "BLOCKED", "Data Leakage Detected", request.user_id)
        raise HTTPException(status_code=502, detail="Response suppressed due to Data Leakage Policy.")

    auditor.log_event("TRANSACTION_COMPLETE", transaction_id, "SUCCESS", "Request fulfilled", request.user_id)
    
    return {
        "id": transaction_id,
        "choices": [{"message": {"role": "assistant", "content": safe_response}}]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
