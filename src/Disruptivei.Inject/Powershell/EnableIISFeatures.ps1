param (
    [String]$logFile
)

Start-Transcript -Path $logFile
Write-Warning "Started script"

# Enable IIS and common components
$features = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-HttpErrors",
    "IIS-ApplicationDevelopment",
    "IIS-ASPNET",
    "IIS-ASPNET45",
    "IIS-NetFxExtensibility",
    "IIS-NetFxExtensibility45",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-RequestMonitor",
    "IIS-HttpTracing",
    "IIS-Security",
    "IIS-BasicAuthentication",
    "IIS-WindowsAuthentication",
    "IIS-Filtering",
    "IIS-Performance",
    "IIS-HttpCompressionStatic",
    "IIS-HttpCompressionDynamic",
    "IIS-ManagementConsole",
    "WCF-HTTP-Activation45",
    "WCF-Pipe-Activation45",
    "WCF-TCP-Activation45",
    "WCF-MSMQ-Activation45"
)

foreach ($feature in $features) {
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to enable $feature"
        Write-Warning $_    
    }
}

# Additional Windows Capabilities, if needed
# Example: Add-WindowsCapability -Online -Name "XPS.Viewer~~~~0.0.1.0"

Stop-Transcript
