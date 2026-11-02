<#
.SYNOPSIS
    Registers "cra run" in the Windows Task Scheduler: every 4 hours, for the current user only.

.DESCRIPTION
    What it does, in simple words:
      * It creates ONE scheduled task called "CRA Copilot - cra run".
      * The task starts "python -m src run" from the project folder every 4 hours (QUESTIONS.md decision 5).
      * One run may take at most 30 minutes. After that Windows stops it (QUESTIONS.md S10).
      * It runs as YOU, only while you are logged on. No password is stored and no administrator rights are used.
      * If a run is still going when the next one is due, the new one is skipped (never two at once).
      * If the computer was off at the planned time, the run starts as soon as the computer is on again.
    What it does NOT do: it does not start the task, it does not change any other setting of Windows,
    and it does not replace an existing task with the same name.
    The task only runs "cra run". It never sends anything, and it cannot approve anything: approving needs a human at a keyboard.

    Try it first with -WhatIf: it then only shows what it WOULD do.

.PARAMETER SbomPath
    The SBOM file to check. Default: the fake demo product in demo-data.

.PARAMETER ConfigPath
    The product config file. Default: the fake demo product in demo-data.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\register-schedule.ps1 -WhatIf

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\register-schedule.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SbomPath,
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

$TaskName = "CRA Copilot - cra run"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $SbomPath) { $SbomPath = Join-Path $ProjectRoot "demo-data\demo-thermostat-sbom.json" }
if (-not $ConfigPath) { $ConfigPath = Join-Path $ProjectRoot "demo-data\demo-product-config.json" }

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
foreach ($required in @($Python, $SbomPath, $ConfigPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "File not found: $required"
    }
}
$SbomPath = (Resolve-Path -LiteralPath $SbomPath).Path
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
# A quote or a shell character in a path would change what the task runs, and a network path would open a connection: refuse both.
foreach ($path in @($ProjectRoot, $SbomPath, $ConfigPath)) {
    if ($path -match '["`$%&;^|<>!]') {
        throw "This path has a special character and cannot be used safely in a task: $path"
    }
    if ($path.StartsWith("\\")) {
        throw "A network path cannot be used in the task: $path"
    }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "The task '$TaskName' already exists. Run scripts\unregister-schedule.ps1 first if you want to register it again."
}

$arguments = "-m src run --sbom `"$SbomPath`" --config `"$ConfigPath`""
$action = New-ScheduledTaskAction -Execute $Python -Argument $arguments -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration (New-TimeSpan -Days 3650)  # 3650 days = "practically forever"; Windows needs some end for the repetition
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Write-Host "Task name:      $TaskName"
Write-Host "Program:        $Python"
Write-Host "Arguments:      $arguments"
Write-Host "Start in:       $ProjectRoot"
Write-Host "Repeats:        every 4 hours, first run in about 5 minutes"
Write-Host "Longest run:    30 minutes"
Write-Host "Runs as:        $env:USERDOMAIN\$env:USERNAME (only while logged on, no administrator rights)"

if ($PSCmdlet.ShouldProcess($TaskName, "Register the scheduled task")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "CRA Copilot: downloads public vulnerability data and checks the product. Sends nothing. A human approves everything." | Out-Null
    Write-Host "Done. The task is registered. Look at it in the Task Scheduler app, and run '.venv\Scripts\python -m src status' later to see the runs."
}
