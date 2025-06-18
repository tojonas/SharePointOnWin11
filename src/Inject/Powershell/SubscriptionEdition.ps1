Param(
    [Parameter(Mandatory = $true)]
    [String]$LogFile,
    [Parameter(Mandatory = $false)]
    [String]$WindowsSource
)

Start-Transcript -Path $LogFile

# List of features/capabilities to enable
$features = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-HttpErrors",
    "IIS-ApplicationDevelopment",
    "IIS-ASPNET45",
    "IIS-NetFxExtensibility45",
    "IIS-ISAPIFilter",
    "IIS-ISAPIExtensions",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-HttpTracing",
    "IIS-Security",
    "IIS-BasicAuthentication",
    "IIS-WindowsAuthentication",
    "IIS-RequestFiltering",
    "IIS-Performance",
    "IIS-HttpCompressionStatic",
    "IIS-HttpCompressionDynamic",
    "WAS-WindowsActivationService",
    "WAS-ProcessModel",
    "WAS-ConfigAPIs",
    "IIS-WCFHttpActivation45",
    "IIS-WCFNonHttpActivation"
)

foreach ($feature in $features) {
    try {
        if ($PSBoundParameters.ContainsKey('WindowsSource')) {
            DISM /Online /Enable-Feature /FeatureName:$feature /LimitAccess /Source:$WindowsSource /All
        } else {
            DISM /Online /Enable-Feature /FeatureName:$feature /All
        }
    }
    catch {
        Write-Error "Failed to enable feature: $feature"
        Stop-Transcript
        $host.SetShouldExit(1000)
        exit
    }
}

# Check if reboot is required
$dismResult = DISM /Online /Get-CurrentEdition
if ($LASTEXITCODE -eq 3010) {
    Stop-Transcript
    $host.SetShouldExit(3010)
} else {
    Stop-Transcript
}
