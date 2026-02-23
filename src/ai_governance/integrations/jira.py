"""Jira webhook integration.

Sends policy violation alerts to Jira via automation webhooks.
Runs as an async background task so it doesn't block the API response.
"""

import logging

import httpx

logger = logging.getLogger(__name__)


async def notify_jira(
    webhook_url: str,
    transaction_id: str,
    user_id: str,
    violation_summary: str,
) -> None:
    """Fire a Jira incident ticket for a policy violation.

    This is designed to be called via FastAPI's BackgroundTasks
    so it runs after the response is sent to the client.

    Args:
        webhook_url: Jira automation webhook URL. If empty, does nothing.
        transaction_id: The governance transaction ID for traceability.
        user_id: Identity of the user who triggered the violation.
        violation_summary: Brief description of what was detected.
    """
    if not webhook_url:
        return

    payload = {
        "summary": f"AI Governance Alert: Policy Violation [{transaction_id[:8]}]",
        "description": (
            f"Transaction ID: {transaction_id}\n"
            f"User: {user_id}\n"
            f"Violations: {violation_summary}\n"
            f"Action Required: Investigate and determine if this was intentional."
        ),
        "issuetype": "Incident",
        "priority": "High",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info("Jira ticket created for transaction %s", transaction_id)
    except httpx.HTTPStatusError as e:
        logger.error(
            "Jira webhook returned %d for transaction %s: %s",
            e.response.status_code,
            transaction_id,
            e.response.text[:200],
        )
    except httpx.RequestError as e:
        logger.error("Jira webhook request failed for transaction %s: %s", transaction_id, e)
