function Get-SigSciAgentVersion
{
    param ([string]$AgentPath = "C:\Program Files\Signal Sciences\Agent\sigsci-agent.exe")
    try
    {
        $output = & $AgentPath --version 2>&1
        return $output
    }
    catch
    {
        Write-Host "Error occurred while getting the agent version."
        return $null
    }
}

function Get-SigSciAgentLatestVersion
{
    param ([string]$Url = "https://dl.signalsciences.net/sigsci-agent/VERSION")
    try
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $Url
        if ($response.StatusCode -eq 200)
        {
            $versionString = [System.Text.Encoding]::ASCII.GetString($response.Content)
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
        Write-Host "Error occurred while retrieving the agent latest version:"
        Write-Host $_.Exception.Message
        return $null
    }
}

function New-DestinationFolder
{
    param ([string]$TargetPath)
    if (-Not(Test-Path -Path $targetPath -PathType Container))
    {
        New-Item -ItemType Directory -Path $TargetPath -Force
        Write-Host "Destination folder created: $TargetPath"
    }
    else
    {
        Write-Host "Destination folder already exists: $TargetPath"
    }
}

function Invoke-SigSciAgentDownload
{
    param ([string]$AgentVersion, [string]$DownloadFolder)
    $Url = "https://dl.signalsciences.net/sigsci-agent/$AgentVersion/windows/sigsci-agent_$AgentVersion.msi"
    $DownloadPath = "$DownloadFolder\sigsci-agent_$AgentVersion.msi"
    New-DestinationFolder -TargetPath $DownloadFolder
    try
    {
        Invoke-WebRequest -Uri $Url -OutFile $DownloadPath
        Write-Host "Agent download completed."
    }
    catch
    {
        Write-Host "Error occurred whild downloading the agent file:"
        Write-Host $_.Exception.Message
    }
}

function Install-SigSciAgent
{
    param ([string]$MsiPath)
    try
    {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait
        Write-Host "Agent installation completed."
    }
    catch
    {
        Write-Host "Error occurred while installing the agent:"
        Write-Host $_.Exception.Message
    }
}

function Start-SigSciAgentService
{
    try
    {
        Start-Service -Name "sigsci-agent"
        Write-Host "sigsci-agent service started."
    }
    catch
    {
        Write-Host "Error occurred while starting the sigsci-agent services:"
        Write-Host $_.Exception.Message
    }

    $serviceStatus = Get-Service -Name "sigsci-agent"
    if ($serviceStatus.Status -eq "Running")
    {
        Write-Host "sigsci-agent service is running."
    }
    else
    {
        Write-Host "sigsci-agent service is not running or could not be started."
    }
}

function Test-IISStatus
{
    $serviceName = "W3SVC"
    try
    {
        $serviceStatus = Get-Service -Name $serviceName
        if ($serviceStatus.Status -eq "Running")
        {
            Write-Host "IIS (W3SVC) is running."
            return $true
        }
        else
        {
            Write-Host "IIS (W3SVC) is not running."
            return $false
        }
        return
    }
    catch
    {
        Write-Host "Error occurred while checking the status of IIS (W3SVC). It may not be installed or running:"
        Write-Host $_.Exception.Message
        return $false
    }
}

function Get-IISModuleVersion
{
    param ([string]$iisModulePath)
    try
    {
        $output = & $iisModulePath Version 2>&1
        $versionPattern = 'v(\d+(\.\d+){2,3})'
        $version = $output | Select-String -Pattern $versionPattern | ForEach-Object { $_.Matches.Groups[1].Value }
        return $version
    }
    catch
    {
        Write-Host "Error occurred while getting the iis module version."
        return $null
    }
}

function Get-IISModuleLatestVersion
{
    param ([string]$Url = "https://dl.signalsciences.net/sigsci-module-iis/VERSION")
    try
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $Url
        if ($response.StatusCode -eq 200)
        {
            return $response.Content.Trim()
        }
        else
        {
            Write-Host "Error: The server returned a non-successful status code: $( $response.StatusCode )"
            return $null
        }
    }
    catch
    {
        Write-Host "Error occurred while retrieving the iis module latest version:"
        Write-Host $_.Exception.Message
        return $null
    }
}

function Invoke-IISModuleDownload
{
    param ([string]$moduleVersion, [string]$downloadFolder)
    $Url = "https://dl.signalsciences.net/sigsci-module-iis/$moduleVersion/sigsci-module-iis-x64-$moduleVersion.msi"
    $DownloadPath = "$downloadFolder\sigsci-module-iis-x64-$moduleVersion.msi"
    New-DestinationFolder -TargetPath $downloadFolder
    try
    {
        Invoke-WebRequest -Uri $Url -OutFile $DownloadPath
        Write-Host "iis module download completed."
    }
    catch
    {
        Write-Host "Error occurred whild downloading the iis module file:"
        Write-Host $_.Exception.Message
    }
}

function Install-IISModule
{
    param ([string]$MsiPath)
    try
    {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" /quiet /norestart" -Wait
        Write-Host "iis module installation completed."
    }
    catch
    {
        Write-Host "Error occurred while installing the iis module:"
        Write-Host $_.Exception.Message
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-Not$isAdmin)
{
    Write-Host "Please run this script as an administrator."
    Exit 1
}

$agentPath = "C:\Program Files\Signal Sciences\Agent\sigsci-agent.exe"
$agentVersion = Get-SigSciAgentVersion
$agentLatestVersion = Get-SigSciAgentLatestVersion
$downloadFolder = "C:\temp\signal-sciences"

if ((-Not(Test-Path -Path $agentPath -PathType Leaf)) -or (-Not$agentVersion) -or ([Version]$agentVersion -lt [Version]$agentLatestVersion))
{
    Invoke-SigSciAgentDownload -AgentVersion $agentLatestVersion -DownloadFolder $downloadFolder
    Install-SigSciAgent -MsiPath "$downloadFolder\sigsci-agent_$agentLatestVersion.msi"
    Start-SigSciAgentService
}

if (-Not(Test-IISStatus))
{
    Write-Host "IIS (W3SVC) may not be installed or running."
    Exit 1
}

$modulePath = "C:\Program Files\Signal Sciences\IIS Module\SigsciCtl.exe"
$moduleVersion = Get-IISModuleVersion -iisModulePath $modulePath
$moduleLatestVersion = Get-IISModuleLatestVersion

if ((-Not(Test-Path -Path $modulePath -PathType Leaf)) -or (-Not$moduleVersion) -or ([Version]$moduleVersion -lt [Version]$moduleLatestVersion))
{
    Invoke-IISModuleDownload -moduleVersion $moduleLatestVersion -DownloadFolder $downloadFolder
    Install-IISModule -MsiPath "$downloadFolder\sigsci-module-iis-x64-$moduleLatestVersion.msi"
}