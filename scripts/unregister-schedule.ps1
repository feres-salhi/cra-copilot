<#
.SYNOPSIS
    Removes the scheduled task "CRA Copilot - cra run" that register-schedule.ps1 made.

.DESCRIPTION
    It removes only the task with exactly this name. No other task and no other setting is touched.
    Try it first with -WhatIf: it then only shows what it WOULD do.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\unregister-schedule.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = "Stop"

$TaskName = "CRA Copilot - cra run"

if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    Write-Host "There is no task called '$TaskName'. Nothing to remove."
    return
}

if ($PSCmdlet.ShouldProcess($TaskName, "Remove the scheduled task")) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Done. The task '$TaskName' was removed."
}
