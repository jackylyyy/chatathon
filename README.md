# chatathon
Chatathon 09/19/2026

https://prod.liveshare.vsengsaas.visualstudio.com/join?6838BB6AED1109AA04B6E47CC70F29DF03E7

lock in

Where the gaps are

Snyk's four initiatives cluster around agentic AI writing code (Evo, Malicious Code Defense) and testing/monitoring systems after they're built (COS, Runtime Insights). Two things are notably not covered yet:

The moment before code is written — when a developer (or an AI agent) is prompting, planning, or picking a package/pattern. Snyk's remediation agent fixes vulnerabilities after they exist. Nothing in their list stops a vulnerability from being introduced in the first place by an AI coding assistant that doesn't know better.
Explainability for non-experts — all four initiatives are built for security teams. There's no mention of helping an average developer (who isn't a security person) actually understand why something is risky, in language they'd get.

That's your opening: the "understand" and "prevent-at-the-source" layer, not another scanner.

A few concrete pitches

1. "Agent Conscience" — a real-time guardrail for AI coding agents
A lightweight proxy/plugin that sits between an AI coding agent (Claude Code, Cursor, Copilot) and the codebase. Before the agent's suggested diff gets applied, it's checked against a ruleset (hardcoded secrets, unsafe deserialization, injection patterns, vulnerable dependency versions) and — critically — the agent gets a natural-language explanation injected back into its context ("this uses eval() on user input, which enables code injection — here's a safer pattern") so it self-corrects instead of just getting blocked. This directly extends Snyk's Malicious Code Defense angle but targets the authoring moment instead of post-hoc scanning.

2. "Why This Matters" — a plain-English vulnerability explainer
Takes a Snyk (or any SCA/SAST) scan output — usually a wall of CVE IDs and severity scores — and turns each finding into: what it means in this specific codebase, a realistic attack scenario ("an attacker could do X because Y"), and a prioritized fix path. This is a great chatathon demo because it's very visual and relatable — judges immediately get why a junior dev would want it. Complements Runtime Insights by making prioritization human-readable, not just risk-scored.

3. "Agent Provenance Tracker" — audit trail for autonomous agent actions
As agents get more autonomous (per Evo's ADE vision), nobody's tracking why an agent made a given change. This tool logs every agent-authored commit with the reasoning, prompt lineage, and which packages/patterns it introduced, then flags commits where the agent's stated reasoning doesn't match the actual diff (a mismatch is itself a red flag — could indicate injected instructions or drift). This is squarely in the "govern autonomous AI agents" space Snyk explicitly says is their focus.

4. "Dependency Trust Score, Explained" — for a new package an AI agent wants to install, generate a plain-language trust briefing (maintainer activity, typosquat risk, recent CVE history, unusual install scripts) before the agent adds it to package.json, not after a scan catches it.

My recommendation for a chatathon

Go with #1 (Agent Conscience) or #2 (Why This Matters) — both are scoped enough to build a working demo in a day or two, and both tell a clear story: "Snyk secures the code that exists; we secure the moment it's being written / the moment someone has to understand it."

#2 is the safer bet if your team is smaller or less experienced with agent tooling — it's essentially a well-designed LLM pipeline over scan JSON output, very demoable, and directly solves "spot, understand, or fix" as literally stated in your prompt. #1 is more ambitious and more impressive if you can pull it off, since it's genuinely novel and matches Snyk's stated direction almost exactly.

Want me to sketch out an actual architecture and demo script for one of these — like what the judges would see in a 5-minute walkthrough?