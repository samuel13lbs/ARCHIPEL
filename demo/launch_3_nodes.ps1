param(
    [int]$PortA = 7777,
    [int]$PortB = 7778,
    [int]$PortC = 7779,
    [string]$StateDir = ".archipel",
    [switch]$DryRun
)

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonPath = "src"

$commands = @(
    "`$env:PYTHONPATH='$pythonPath'; python -m cli.archipel start --port $PortA --state-dir '$StateDir'",
    "`$env:PYTHONPATH='$pythonPath'; python -m cli.archipel start --port $PortB --state-dir '$StateDir'",
    "`$env:PYTHONPATH='$pythonPath'; python -m cli.archipel start --port $PortC --state-dir '$StateDir'"
)

Write-Host "Project root: $projectRoot"
Write-Host "Ports: $PortA, $PortB, $PortC"
Write-Host "StateDir: $StateDir"

for ($i = 0; $i -lt $commands.Count; $i++) {
    $title = "ARCHIPEL node $($i + 1) port $(@($PortA,$PortB,$PortC)[$i])"
    $cmd = $commands[$i]

    if ($DryRun) {
        Write-Host "[DRYRUN] $title"
        Write-Host "         $cmd"
        continue
    }

    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "Set-Location '$projectRoot'; `$host.UI.RawUI.WindowTitle='$title'; $cmd"
    )
}

if ($DryRun) {
    Write-Host "Dry run complete."
} else {
    Write-Host "3 nodes launched in separate PowerShell windows."
}
