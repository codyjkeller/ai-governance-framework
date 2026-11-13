# AI Governance Content

## Summary for executives

The proxy in this repository controls what data reaches AI models. It does not tell you **which AI uses exist, who owns them, or how risky each one is**. This folder does.

It gives you three things:

1. **An inventory** of every AI use case, in one file.
2. **A risk tier** for each use case (high, moderate or low), decided by simple rules.
3. **A check** that runs on every change and fails if an entry is incomplete, under-rated or overdue for review.

The approach follows the NIST AI Risk Management Framework (AI RMF 1.0), which asks organizations to keep an inventory of their AI systems and manage each according to its risk.

## What is in this folder

| File | What it is for |
|---|---|
| `ai_inventory.yaml` | The inventory. One entry per AI use case. Ships with three made-up examples. |
| `risk_tiering.md` | How a use case gets its tier, and what each tier requires. |
| `intake_form.md` | Questions a team answers when it wants to start using AI for something new. |

## How to use it

1. **A team wants to use AI.** They fill in `intake_form.md` and send it to the security or GRC team.
2. **GRC assigns a tier** using `risk_tiering.md` and adds an entry to `ai_inventory.yaml` with status `proposed`.
3. **The approver signs off.** Set the status to `approved`, and fill in `approved_by`, `approved_on` and `next_review`.
4. **Run the check:**

   ```bash
   ai-gov-inventory
   ```

   It prints any problems and exits with an error if there are any, so it can run in CI.
5. **Review on schedule.** When `next_review` passes, the check reports the entry as overdue.
6. **Retire, do not delete.** When a use case ends, set its status to `retired` so the record is kept.

## What the check looks for

- Every required field is filled in, and each id is used once.
- The tier is at least as strict as the entry's own answers require. An entry that handles CJI or PHI cannot be marked tier 3.
- Tier 1 entries describe their human oversight.
- Approved entries have an approver, an approval date and a review date inside the limit for their tier.
- Models used through the proxy are on the proxy's approved model list.
- Reviews are not overdue. Pass `--allow-overdue` to report these without failing.

## What it does not do

- It does not find AI use nobody reported. Pair it with your procurement and SaaS discovery processes.
- It does not change what the proxy allows. The proxy's rules are in `policies/generative_ai_aup.yaml`.
- The tier rules are a starting point. Adjust them to your own risk tolerance.
