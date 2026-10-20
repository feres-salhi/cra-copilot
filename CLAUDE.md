\# CRA Copilot — Project Rulebook



\## What this project is

An open-source tool that helps small manufacturers meet the EU Cyber Resilience Act (CRA) reporting duty:

when a vulnerability in one of their product's software components is actively exploited, they must send an early warning within 24 hours.

The tool: (1) reads a product's SBOM, (2) downloads new public vulnerability data daily, (3) matches vulnerabilities to components and checks if they are actively exploited,

(4) uses AI to draft the report text in German and English, (5) fact-checks the draft with code, (6) a human approves before anything is sent.

This is a student portfolio project by Fares Salhi (TU Darmstadt). Language: Python.



\## About the person you are working with

Fares is a beginner. For every step:

\- Explain what you are doing in simple, non-technical words, like to a total beginner.

\- Explain every new term in one plain sentence.

\- Work in small steps. Show what you plan to do before running commands or editing files.

\- After each finished part, recap how it connects to the whole project.



\## Trust rules (never break these)

1\. The AI never decides whether a product is affected. Only normal, testable code decides that. The AI only writes sentences from facts it is given.

2\. Every product name, component, version, vulnerability ID and date in a report must come from the input data. fact\_checker.py must reject any draft that contains facts not found in the data.

3\. Use only FAKE demo data in demo-data/. Never use a real company's product data.

4\. Never write API keys or passwords into code or any file that goes to GitHub. Keys live only in a .env file, and .env must be listed in .gitignore.

5\. Never invent results, numbers or claims for the README or reports. Only write what tests actually showed.

6\. A human always approves a report. The tool never sends anything automatically.



\## Folder structure

\- src/sbom\_reader.py   — part 1: reads the SBOM (the product's software ingredient list)

\- src/news\_watcher.py  — part 2: downloads new vulnerability data

\- src/matcher.py       — part 3: affected? actively exploited?

\- src/report\_writer.py — part 4: AI drafts the report text

\- src/fact\_checker.py  — part 4: code checks every fact in the draft

\- tests/               — automatic tests (pytest) for every part

\- demo-data/           — fake example products only

\- screenshots/         — numbered proof screenshots (NN-description.png), only for important results

\- README.md            — written at the end

\- LAB-NOTES.md         — written last, after the project is finished



\## How every step works

1\. Build one small piece.

2\. Write or update automatic tests for it, run them, and show the result. A step is only done when all tests pass.

3\. Use the code-reviewer subagent and the AI-generated code security auditor subagent to review the new code. Fix serious issues before moving on.

4\. Before any GitHub upload: use the secrets and credential hygiene subagent to check that no keys or passwords leak.

5\. At the end of each phase: run a Strix scan and a penetration-tester subagent review, then fix what matters.



\## Models

\- Daily building: Sonnet.

\- Design decisions and agent-team meetings: Opus.

\- Small chores in subagents: Haiku.

