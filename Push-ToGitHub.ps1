#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot script to push this repo to GitHub under the LuchoBorbon76 account.

.DESCRIPTION
    Initializes git, commits, and pushes to https://github.com/LuchoBorbon76/sql-performance-dashboard.
    You'll be prompted to sign in to GitHub in a browser (via Git Credential Manager) the first time.

.PARAMETER RepoName
    GitHub repository name (default: sql-performance-dashboard)

.PARAMETER GitHubUser
    GitHub username (default: LuchoBorbon76)

.PARAMETER Private
    Create the repo as private. Default is public.

.EXAMPLE
    .\Push-ToGitHub.ps1
    .\Push-ToGitHub.ps1 -Private
#>
param(
    [string]$RepoName    = 'sql-performance-dashboard',
    [string]$GitHubUser  = 'LuchoBorbon76',
    [switch]$Private
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $here

function Test-Command($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

if (-not (Test-Command git)) {
    Write-Host "git not found. Install via: winget install --id Git.Git" -ForegroundColor Red
    exit 1
}

# Step 1: init if needed
if (-not (Test-Path (Join-Path $here '.git'))) {
    Write-Host "==> Initializing git repository..." -ForegroundColor Cyan
    git init -b main
    git config user.name  "Luis Fernando Borbon"
    git config user.email "$GitHubUser@users.noreply.github.com"
}

# Step 2: create the GitHub repo (via API using Git Credential Manager token or gh cli)
$repoUrl = "https://github.com/$GitHubUser/$RepoName.git"
$apiUrl  = "https://api.github.com/repos/$GitHubUser/$RepoName"

Write-Host "==> Checking if GitHub repo exists: $repoUrl" -ForegroundColor Cyan
try {
    $null = Invoke-RestMethod -Uri $apiUrl -Method GET -ErrorAction Stop
    Write-Host "  Repo exists, will push to it" -ForegroundColor Green
} catch {
    Write-Host "  Repo does not exist. Please create it at:" -ForegroundColor Yellow
    Write-Host "  https://github.com/new" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Name:        $RepoName"
    Write-Host "  Owner:       $GitHubUser"
    Write-Host "  Visibility:  $(if($Private){'Private'}else{'Public'})"
    Write-Host "  DO NOT check 'Add a README', 'Add .gitignore', or 'Choose a license' — this script has those."
    Write-Host ""
    $open = Read-Host "Open browser to create it now? [Y/n]"
    if ($open -notmatch '^n') { Start-Process "https://github.com/new" }
    Read-Host "Press Enter after you have created the empty repo"
}

# Step 3: stage + commit
Write-Host "==> Staging files..." -ForegroundColor Cyan
git add -A
$status = git status --porcelain
if (-not $status) {
    Write-Host "  Nothing to commit" -ForegroundColor Yellow
} else {
    git commit -m "Initial commit: SQL Performance Dashboard v1.0.0" | Out-Null
    Write-Host "  Committed" -ForegroundColor Green
}

# Step 4: set remote
$remotes = git remote
if ($remotes -notcontains 'origin') {
    git remote add origin $repoUrl
    Write-Host "==> Added remote 'origin' -> $repoUrl" -ForegroundColor Cyan
} else {
    git remote set-url origin $repoUrl
    Write-Host "==> Updated remote 'origin' -> $repoUrl" -ForegroundColor Cyan
}

# Step 5: push
Write-Host "==> Pushing to GitHub (you may be prompted to sign in)..." -ForegroundColor Cyan
git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Push failed. Common causes:" -ForegroundColor Red
    Write-Host "  * Signed in to a different GitHub account (check Git Credential Manager)"
    Write-Host "  * Repo does not exist yet — create it at https://github.com/new"
    Write-Host "  * Need a Personal Access Token — https://github.com/settings/tokens"
    exit 1
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  Pushed to https://github.com/$GitHubUser/$RepoName" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
