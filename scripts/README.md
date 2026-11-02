# Scripts: run CRA Copilot automatically every 4 hours

These two PowerShell scripts set up (and remove) an automatic run of `cra run` in the **Windows Task Scheduler**.
*Task Scheduler is the part of Windows that starts programs at fixed times.*

**They were written but never run by the assistant** (the work order said you register the task yourself).
The tests only read them and let PowerShell check the spelling; nothing was changed on your computer.

## Why every 4 hours?

The law gives a company only 24 hours after it becomes aware of an actively exploited vulnerability.
If `cra run` ran only once a day, a new case could wait almost a whole day before anyone saw it.
Every 4 hours is your decision from QUESTIONS.md (number 5). `cra status` warns when the last good run is older than 26 hours.

## register-schedule.ps1

Run it from the project folder in PowerShell. **First look at what it would do** (this changes nothing):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\register-schedule.ps1 -WhatIf
```

If you are happy with the lines it prints, run it for real:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\register-schedule.ps1
```

What it sets up, in simple words:

- One task called **CRA Copilot - cra run**.
- It runs `python -m src run` for the fake demo product from `demo-data`. For another product, add
  `-SbomPath <file> -ConfigPath <file>`.
- It starts about 5 minutes after you register it, then **every 4 hours**.
- One run may take **at most 30 minutes**. Then Windows stops it (QUESTIONS.md S10: the run itself has no total time limit).
- It runs as **you**, only while you are logged on. No password is stored. No administrator rights.
- It runs only when a network is available (also on battery). A run that was missed is started once the network is back.
- If a run is still going when the next one is due, the new one is skipped.
- If the computer was off, the run starts when the computer is on again.
- **Keep the project folder private.** The task runs the Python program and the files in `src` unattended. Anyone who can change them can run code as you. A folder under your own user folder is fine; do not put the project in a folder that other users may write to.
- If the task already exists, the script stops and changes nothing. It never starts the task by itself.

## unregister-schedule.ps1

Removes only the task with that exact name. Nothing else.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\unregister-schedule.ps1 -WhatIf
powershell -ExecutionPolicy Bypass -File scripts\unregister-schedule.ps1
```

## What you will see afterwards

- Every run saves a record in `runs\`. Check them with `.venv\Scripts\python -m src status`.
- In the Task Scheduler app, the column "Last Run Result" may show **1** or **3**. That is normal and not an error of Windows:
  `cra run` uses its **exit code** (the number a program returns when it ends) to say "something needs a human"
  (0 = all fine, 1 = incomplete or needs a look, 2 = the SBOM or config file was rejected: a real error, 3 = a possible report case was found).
- The task cannot draft or approve anything: `cra draft` and `cra approve` need a person at the keyboard.
  Every run ends with the list of open cases and their deadlines, and the possible report cases that still have no draft.
  But the screen output of a scheduled run is not shown anywhere. So run `cra run` yourself (or look at the newest file in `runs\`) regularly.
  Nobody is notified automatically yet (a notification is a later improvement).
- The task never sends anything anywhere except the downloads of public data from OSV.dev and CISA.
