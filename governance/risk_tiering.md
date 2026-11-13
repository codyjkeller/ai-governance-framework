# AI Risk Tiering Procedure

## Purpose

Every AI use case gets one of three risk tiers. The tier decides how much review it needs before launch and how often it is looked at again.

The NIST AI RMF does not define tiers. It asks organizations to decide how much risk management each AI system needs. These three tiers are this framework's way of doing that.

## Step 1: Find the tier

Start at the top. The first row that applies sets the tier.

| Tier | Applies when the use case... |
|---|---|
| **1 - High** | Handles Criminal Justice Information (CJI) or Protected Health Information (PHI); **or** its output informs a decision about a person (hiring, eligibility, an investigation); **or** it takes actions without a person approving each one. |
| **2 - Moderate** | Handles personal information (PII) or confidential business data; **or** its output goes to customers or the public. |
| **3 - Low** | Uses only public or internal, non-sensitive data, for internal staff, with a person deciding what to do with the output. |

A reviewer may always choose a stricter tier than the table gives. A reviewer may not choose a more lenient one. The inventory check enforces this.

## Step 2: Apply the requirements for that tier

| Requirement | Tier 1 - High | Tier 2 - Moderate | Tier 3 - Low |
|---|---|---|---|
| Entry in the inventory with a named owner | Yes | Yes | Yes |
| Approval before use | CISO and the data owner | CISO or delegate | GRC team |
| Requests go through the governance proxy | Required | Required | Recommended |
| Vendor security and privacy review | Full review, including contract terms on data use and retention | Standard review | Confirm the vendor is already approved |
| Human oversight | Written description of who checks the output and when | A person reviews output before it leaves the organization | Normal user judgment |
| Testing before launch | Documented tests for accuracy, security and privacy | Spot checks | None required |
| Monitoring after launch | Audit log reviewed on a set schedule; incidents tracked | Audit log reviewed when an alert fires | Audit log kept |
| Review at least every | 6 months | 12 months | 24 months |

For Tier 1 use cases that handle CJI or PHI, also confirm the provider meets the specific requirements of the CJIS Security Policy or HIPAA (for example, a signed CJIS Security Addendum or a Business Associate Agreement) before any data is sent.

## Step 3: Record and review

- Record the tier, the approver and the next review date in `ai_inventory.yaml`.
- Re-tier a use case whenever its data, audience, model or level of autonomy changes.
- When a use case ends, set its status to `retired`. Keep the entry.

## How this maps to the NIST AI RMF

The references are to AI RMF 1.0 (NIST AI 100-1, January 2023). NIST has said a revision is in progress; check the numbering against the current version when it is published.

| Activity in this procedure | AI RMF function | Subcategories it supports |
|---|---|---|
| Keeping the inventory | GOVERN | GOVERN 1.6 |
| Naming an owner and approver | GOVERN | GOVERN 2.1 |
| Setting review frequency by tier | GOVERN | GOVERN 1.3, GOVERN 1.5 |
| Retiring use cases | GOVERN | GOVERN 1.7 |
| Vendor review | GOVERN, MAP | GOVERN 6.1, MAP 4.1 |
| Recording purpose, data and audience (intake form) | MAP | MAP 1.1 |
| Assigning the tier | MAP | MAP 5.1 |
| Defining human oversight | MAP | MAP 3.5 |
| Testing for security and privacy | MEASURE | MEASURE 2.7, MEASURE 2.10 |
| Deciding to approve, restrict or decline | MANAGE | MANAGE 1.1, MANAGE 1.3 |
| Monitoring after launch | MANAGE | MANAGE 4.1 |

The proxy itself supports the MEASURE and MANAGE rows: it enforces the data rules and produces the audit log that monitoring relies on. See `docs/COMPLIANCE_MAPPING.md` for the control mapping to NIST SP 800-53, SOC 2, HIPAA, CJIS and GovRAMP.
