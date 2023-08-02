function Test-IsAdministrator
{
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

function Get-Version
{
    param ([string]$FilePath, [string]$VersionFlag)
    try
    {
        $output = & $FilePath $VersionFlag 2>&1
        $versionPattern = '\d+(\.\d+){0,2}(?:\.\d+)?'
        $version = $output | Select-String -Pattern $versionPattern | ForEach-Object { $_.Matches.Value }
        return $version
    }
    catch
    {
        Write-Host "Error occurred while getting the version from $FilePath :"
        Write-Host $_.Exception.Message
        return $null
    }
}

function Get-LatestVersion
{
    param ([string]$Url)
    try
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $Url
        if ($response.StatusCode -eq 200)
        {
            $versionString = $response.Content
            if ($versionString -is [byte[]])
            {
                $versionString = [System.Text.Encoding]::ASCII.GetString($versionString)
            }
            return $versionString.Trim()
        }
        else
        {
            Write-Host "Error: The server returned a non-successful status code: $( $response.StatusCode )"
            return $null
        }
    }
    catch
    {
        Write-Host "Error occurred while retrieving the latest version from $Url :"
        Write-Host $_.Exception.Message
        return $null
    }
}

function New-DestinationFolder
{
    param ([string]$TargetPath)
    if (-Not(Test-Path -Path $TargetPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $TargetPath -Force
        Write-Host "Destination folder created: $TargetPath"
    }
    else
    {
        Write-Host "Destination folder already exists: $TargetPath"
    }
}

function Invoke-Download
{
    param ([string]$SourceUrl, [string]$TargetPath)
    New-DestinationFolder -TargetPath (Split-Path -Parent $TargetPath)
    try
    {
        Invoke-WebRequest -Uri $SourceUrl -OutFile $TargetPath
        Write-Host "Download completed: $TargetPath"
    }
    catch
    {
        Write-Host "Error occurred whild downloading the file from $SourceUrl :"
        Write-Host $_.Exception.Message
    }
}

function Install-Msi
{
    param ([string]$MsiPath)
    try
    {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait
        Write-Host "Installation completed: $MsiPath"
    }
    catch
    {
        Write-Host "Error occurred while installing $MsiPath :"
        Write-Host $_.Exception.Message
    }
}

function Test-ServiceStatus
{
    param ([string]$ServiceName)
    try
    {
        $serviceStatus = Get-Service -Name $ServiceName
        if ($serviceStatus.Status -eq "Running")
        {
            Write-Host "Service is running: $ServiceName"
            return $true
        }
        else
        {
            Write-Host "Service is not running: $ServiceName"
            return $false
        }
        return
    }
    catch
    {
        Write-Host "Error occurred while checking the status of $ServiceName :"
        Write-Host $_.Exception.Message
        return $false
    }
}

function Start-SpecificService
{
    param ([string]$ServiceName)
    try
    {
        Start-Service -Name $ServiceName
        Write-Host "Started service: $ServiceName"
    }
    catch
    {
        Write-Host "Error occurred while starting service $ServiceName :"
        Write-Host $_.Exception.Message
    }

    Test-ServiceStatus -ServiceName $ServiceName
}

$isAdmin = Test-IsAdministrator
if (-Not$isAdmin)
{
    Write-Host "Please run this script as an administrator."
    Exit 1
}

$agentPath = "C:\Program Files\Signal Sciences\Agent\sigsci-agent.exe"
$agentVersion = Get-Version -FilePath $agentPath -VersionFlag "--version"
$agentLatestVersion = Get-LatestVersion -URl "https://dl.signalsciences.net/sigsci-agent/VERSION"
$downloadFolder = "C:\temp\signal-sciences"

if ((-Not(Test-Path -Path $agentPath -PathType Leaf)) -or (-Not$agentVersion) -or ([Version]$agentVersion -lt [Version]$agentLatestVersion))
{
    $agentDownloadUrl = "https://dl.signalsciences.net/sigsci-agent/$agentLatestVersion/windows/sigsci-agent_$agentLatestVersion.msi"
    $agentDownloadPath = Join-Path $downloadFolder "sigsci-agent_$agentLatestVersion.msi"
    Invoke-Download -SourceUrl $agentDownloadUrl -TargetPath $agentDownloadPath
    Install-Msi -MsiPath $agentDownloadPath
    Start-SpecificService -ServiceName "sigsci-agent"
}

if (-Not(Test-ServiceStatus -ServiceName "W3SVC"))
{
    Write-Host "IIS (W3SVC) may not be installed or running."
    Exit 1
}

$iisModulePath = "C:\Program Files\Signal Sciences\IIS Module\SigsciCtl.exe"
$iisModuleVersion = Get-Version -FilePath $iisModulePath -VersionFlag "Version"
$iisModuleLatestVersion = Get-LatestVersion -Url "https://dl.signalsciences.net/sigsci-module-iis/VERSION"

if ((-Not(Test-Path -Path $iisModulePath -PathType Leaf)) -or (-Not$iisModuleVersion) -or ([Version]$iisModuleVersion -lt [Version]$iisModuleLatestVersion))
{
    $iisModuleDownloadUrl = "https://dl.signalsciences.net/sigsci-module-iis/$iisModuleLatestVersion/sigsci-module-iis-x64-$iisModuleLatestVersion.msi"
    $iisMOduleDownloadPath = Join-Path $downloadFolder "sigsci-module-iis-x64-$iisModuleLatestVersion.msi"
    Invoke-Download -SourceUrl $iisModuleDownloadUrl -TargetPath $iisMOduleDownloadPath
    Install-Msi -MsiPath $iisMOduleDownloadPath
}