<#
.SYNOPSIS
    WinGet Manifest creation helper script
.DESCRIPTION
    This file intends to help you generate a manifest for publishing
    to the Windows Package Manager repository.

    It'll attempt to download an installer from the user-provided URL to calculate
    a checksum. That checksum and the rest of the input data will be compiled into
    a set of .YAML files.
.EXAMPLE
    PS C:\Projects\winget-pkgs> Get-Help .\Tools\YamlCreate.ps1 -Full
    Show this script's help
.EXAMPLE
    PS C:\Projects\winget-pkgs> .\Tools\YamlCreate.ps1
    Run the script to create a manifest file
.NOTES
    Please file an issue if you run into errors with this script:
    https://github.com/microsoft/winget-pkgs/issues
.LINK
    https://github.com/microsoft/winget-pkgs/blob/master/Tools/YamlCreate.ps1
#>

#Requires -Version 7

param
(
  [Parameter(Mandatory = $false)]
  [string] $PackageIdentifier,
  [Parameter(Mandatory = $false)]
  [string] $PackageVersion,
  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 6)]
  [int] $Mode,
  [switch] $Settings,
  [switch] $AutoUpgrade,
  [switch] $Help,
  [switch] $SkipPRCheck,
  [switch] $Preserve
)

enum ScriptModes {
  FullUpdate = 1
  QuickUpdateVersion = 2
  MetadataUpdate = 3
  NewLocale = 4
  RemoveManifest = 5
  MoveManifests = 6
  CreateManifest # This is explicitly not assigned a value as it is an internal mode and is not user selectable
  AutomaticUpdate = [int]::MaxValue
}

enum AlwaysNeverOption {
  Ask
  Never
  Always
}

enum ManifestType {
  singleton
  installer
  locale
  defaultLocale
  version
}

####
# Description: Removes files and folders from the file system
# Inputs: List of paths to remove
# Outputs: None
####
function Invoke-FileCleanup {
  param (
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowEmptyCollection()]
    [String[]] $FilePaths
  )
  if (!$FilePaths) { return }
  foreach ($path in $FilePaths) {
    Write-Debug "Removing $path"
    if (Test-Path $path) { Remove-Item -Path $path -Recurse }
    else { Write-Warning "Could not remove $path as it does not exist" }
  }
}

####
# Description: Cleans up resources used by the script and then exits
# Inputs: Exit code
# Outputs: None
####
function Invoke-CleanExit {
  param (
    [Parameter(Mandatory = $true)]
    [int] $ExitCode
  )
  Invoke-FileCleanup -FilePaths $script:CleanupPaths

  # Reset variables that were changed
  Write-Debug 'Restoring saved settings'

  if ($script:OriginalRemoteUpstreamUri) { git remote set-url upstream $script:OriginalRemoteUpstreamUri } # This should be null or the original Uri
  [Threading.Thread]::CurrentThread.CurrentUICulture = $script:OriginalUICulture
  [Threading.Thread]::CurrentThread.CurrentCulture = $script:OriginalCulture
  $global:ProgressPreference = $script:OriginalGlobalProgressPreference
  $ProgressPreference = $script:OriginalProgressPreference
  $global:InformationPreference = $script:OriginalGlobalInformationPreference
  $InformationPreference = $script:OriginalInformationPreference
  $ErrorActionPreference = $script:OriginalErrorActionPreference
  $PSDefaultParameterValues = $script:OriginalDefaultParameters
  $ofs = $script:OriginalOfs
  $env:TEMP = $script:OriginalTempDirectory
  $env:PSModulePath = $script:OriginalPSModulePath
  $global:DebugPreference = $script:OriginalGlobalDebugPreference
  $DebugPreference = $script:OriginalDebugPreference
  $global:VerbosePreference = $script:OriginalGlobalVerbosePreference
  $VerbosePreference = $script:OriginalVerbosePreference

  # Exit
  Write-Debug "Exiting ($ExitCode)"
  exit $ExitCode
}

####
# Description: Ensures that a folder is present. Creates it if it does not exist
# Inputs: Path to folder
# Outputs: Boolean. True if path exists or was created; False if otherwise
####
function Initialize-Folder {
  param (
    [Parameter(Mandatory = $true)]
    [String] $FolderPath
  )
  $FolderPath = [System.Io.Path]::GetFullPath($FolderPath) # Normalize the path just in case the separation characters weren't quite right, or dot notation was used
  if (Test-Path -Path $FolderPath -PathType Container) { return $true } # The path exists and is a folder
  if (Test-Path -Path $FolderPath) { return $false } # The path exists but was not a folder
  Write-Debug "Initializing folder at $FolderPath"
  $directorySeparator = [System.IO.Path]::DirectorySeparatorChar

  # Build the path up one part at a time. This is safer than using the `-Force` parameter on New-Item to create the directory
  foreach ($pathPart in $FolderPath.Split($directorySeparator)) {
    $builtPath += $pathPart + $directorySeparator
    if (!(Test-Path -Path $builtPath)) { New-Item -Path $builtPath -ItemType Directory | Out-Null }
  }

  # Make sure that the path was actually created
  return Test-Path -Path $FolderPath
}

####
# Description: Gets the setting enum option associated with multi-state settings
# Inputs: Setting Text
# Outputs: Setting mode from enum
####
filter Initialize-AlwaysNeverSetting {
  # Case insensitively convert strings to enum
  if ($_ -eq 'always') { return [AlwaysNeverOption]::Always }
  if ($_ -eq 'never') { return [AlwaysNeverOption]::Never }
  # If no match, return the default
  return [AlwaysNeverOption]::Ask
}

####
# Description: Ensures that the script is running inside a Git repository and the Upstream URL is set correctly
# Inputs: None
# Outputs: None
####
function Initialize-ScriptRepository {
  # If Git is not installed, we can't check if the script is inside a repository
  if (!$script:GitIsPresent) {
    Write-Error 'This script has a dependency on Git, but no installation was found' -ErrorAction Stop
  }
  # `git rev-parse` will indicate the base of the repository, which will be used for determining the location of manifest files
  try {
    $script:RepositoryBase = (Resolve-Path $(git rev-parse --show-toplevel)).Path
  } catch {
    Write-Error 'This script must be run from inside a clone of the winget-pkgs repository' -ErrorAction Stop
  }

  # Get the URL for the `upstream` remote
  ($script:OriginalRemoteUpstreamUri = $(git remote get-url upstream)) *> $null
  # If the `upstream` remote exists, set it to the upstream remote that is needed for the script
  if ($script:OriginalRemoteUpstreamUri) {
    Write-Verbose "Upstream already exists with URI (${script:OriginalRemoteUpstreamUri}). Temporarily setting ${script:WinGetUpstreamUri} as remote upstream"
    git remote set-url upstream $script:WinGetUpstreamUri
  } else {
    # Otherwise, permanently set the remote
    Write-Information "${vtForegroundYellow}Upstream does not exist. Permanently adding ${vtForegroundBlue}${vtUnderline}${script:WinGetUpstreamUri}${vtNotUnderline}${vtForegroundYellow} as remote upstream${vtDefault}"
    git remote add upstream $script:WinGetUpstreamUri
  }
}

####
# Description: Ensures a PowerShell module is installed
# Inputs: PowerShell Module Name
# Outputs: None
####
function Initialize-Module {
  param (
    [Parameter(Mandatory = $true)]
    [String] $Name,
    [Parameter(Mandatory = $false)]
    [String[]] $Cmdlet,
    [Parameter(Mandatory = $false)]
    [String[]] $Function
  )

  $NuGetVersion = (Get-PackageProvider).Where({ $_.Name -ceq 'NuGet' }).Version
  $installedModules = Get-Module -ListAvailable -Name $Name

  # Ensure NuGet is installed and up to date
  # If the NuGet Package Provider is not installed, the version will be null, which will satisfy the conditional
  if ($NuGetVersion -lt $script:NuGetMinimumVersion) {
    try {
      Write-Debug 'NuGet Package Provider was not found, it will be installed'
      # This might fail if the user is not an administrator, so catch the errors
      Install-PackageProvider -Name NuGet -MinimumVersion $script:NuGetMinimumVersion.ToString() -Force -Scope CurrentUser
    } catch {
      Write-Error 'Could not install the NuGet package provider which is required to install script dependencies.' -ErrorAction Continue
      Write-Error "You may be able to resolve this by running: Install-PackageProvider -Name NuGet -MinimumVersion $($script:NuGetMinimumVersion.ToString())"
    }
  }

  Write-Verbose "Ensuring PowerShell module '$Name' is installed"
  if ($installedModules) {
    # If the module is installed, attempt to upgrade it
    Write-Debug "Found $Name in installed modules"
  } else {
    # If the module is not installed, attempt to install it
    try {
      Install-Module -Name $Name -Force -Repository PSGallery -Scope CurrentUser
    } catch {
      Write-Error "$Name was unable to be installed successfully"
    }
  }
  # Verify the module is installed and present
  try {
    if (!(Get-Module -Name $Name)) {
      $importParameters = @{Name = $Name; Scope = 'Local' } # Force the module to be imported into the local scope to avoid changing the global scope
      if ($PSBoundParameters.ContainsKey('Cmdlet')) { $importParameters['Cmdlet'] = $Cmdlet }
      if ($PSBoundParameters.ContainsKey('Function')) { $importParameters['Function'] = $Function }

      Import-Module @importParameters
    }
  } catch {
    Write-Error "$Name was found in available modules, but could not be imported"
  }
}

####
# Description: Gets the location that manifests should be created based on the current state of the script
# Inputs: None
# Outputs: Path pointing to the folder where manifests should be
####
function Get-ManifestsFolder {
  # First check if this script is in a copy of winget-pkgs repo
  if ($script:RepositoryBase -and $script:RepositoryBase -match "\$([System.IO.Path]::DirectorySeparatorChar)winget-pkgs$") {
    return Join-Path -Path $script:RepositoryBase -ChildPath $script:ManfiestsFolderName
  }
  # Second check based on where the script is being run
  $alternatePath = Join-Path -Path (Get-Item $PSScriptRoot).Parent -ChildPath $script:ManfiestsFolderName
  elseif (Test-Path $alternatePath) {
    return $alternatePath
  }
  # If those fail, use the present working directory
  return Join-Path -Path $PWD -ChildPath $script:ManfiestsFolderName
}

# Versions
Write-Debug 'Setting required versions'
$script:ScriptVersion = '3.0.0-alpha'
$script:NuGetMinimumVersion = [System.Version]::Parse('2.8.5.201')

# Flags
Write-Debug 'Checking for supported features'
$script:isInteractive = $null -ne (Get-Host).UI.RawUI
$script:WinGetIsPresent = Get-Command 'winget' -ErrorAction SilentlyContinue
$script:GitIsPresent = Get-Command 'git' -ErrorAction SilentlyContinue
$script:GhIsPresent = Get-Command 'gh' -ErrorAction SilentlyContinue
$script:SandboxIsPresent = Get-Command 'WindowsSandbox' -ErrorAction SilentlyContinue

# Settings Storage
Write-Debug 'Storing current settings'
# Progress preference has to be set globally for Expand-Archive
# https://github.com/PowerShell/Microsoft.PowerShell.Archive/issues/77#issuecomment-601947496
$script:OriginalGlobalProgressPreference = $global:ProgressPreference
$script:OriginalProgressPreference = $ProgressPreference
$script:OriginalGlobalInformationPreference = $global:InformationPreference
$script:OriginalInformationPreference = $InformationPreference
$script:OriginalErrorActionPreference = $ErrorActionPreference
$script:OriginalUICulture = [Threading.Thread]::CurrentThread.CurrentUICulture
$script:OriginalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
$script:OriginalDefaultParameters = $PSDefaultParameterValues
$script:OriginalOfs = $ofs
$script:OriginalTempDirectory = $env:TEMP
$script:OriginalRemoteUpstreamUri = $null # Initialized for later use
$script:OriginalPSModulePath = $env:PSModulePath
$script:OriginalGlobalDebugPreference = $global:DebugPreference
$script:OriginalDebugPreference = $DebugPreference
$script:OriginalGlobalVerbosePreference = $global:VerbosePreference
$script:OriginalVerbosePreference = $VerbosePreference

# Script Behavior
Write-Debug 'Creating internal state'
$script:HeaderText = '# Created with YamlCreate.ps1 v'
$script:ScriptHeader = "${script:HeaderText}${script:ScriptVersion}"
$script:UserAgent = 'Microsoft-Delivery-Optimization/10.1'
$script:WinGetUpstreamUri = 'https://github.com/microsoft/winget-pkgs.git'
$script:RunHash = $(Get-FileHash -InputStream $([IO.MemoryStream]::new([byte[]][char[]]$(Get-Date).Ticks.ToString()))).Hash.Substring(0, 8)
$script:SettingsPath = Join-Path $(if ($isWindows) { $env:LOCALAPPDATA } else { $env:HOME + '/.config' } ) -ChildPath 'YamlCreate2' -AdditionalChildPath 'Settings.yaml'
$script:ManfiestsFolderName = 'manifests'

# Misc
$script:Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$script:CleanupPaths = @()

# Terminal Setup
Write-Debug 'Setting required termininal properties'
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
$global:ProgressPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$global:InformationPreference = 'Continue'
$InformationPreference = 'Continue'
$ErrorActionPreference = 'Continue'
$PSDefaultParameterValues = @{
  '*:Encoding'               = 'UTF8'
  'ConvertTo-Json:Depth'     = '10'
  'ConvertFrom-Yaml:Ordered' = $true
}
$ofs = ', '
if (!$isWindows) { $env:TEMP = '/tmp/' }

# If the script was run with -Debug, set the default parameter for all commands to include -Debug
if ($PSCmdlet.MyInvocation.BoundParameters['Debug']) {
  $global:DebugPreference = 'Continue'
  $DebugPreference = 'Continue'
}

# If the script was run with -Verbose, set the default parameter for all commands to include -Verbose
if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
  $global:VerbosePreference = 'Continue'
  $VerbosePreference = 'Continue'
}

$env:PSModulePath = $env:PSModulePath + ';' + (Join-Path -Path $PSScriptRoot -ChildPath 'Modules') # Add the local modules to the PSModulePath
Import-Module -Name 'VirtualTerminal' -Scope Global -Force -ErrorAction 'SilentlyContinue' # Local module for VT codes

#### Start of Early Exiting Main-Functions
if ($help) {
  Write-Information "${vtForegroundGreen}For full documentation of the script, see ${vtForegroundBlue}${vtUnderline}https://github.com/microsoft/winget-pkgs/tree/master/doc/tools/YamlCreate.md${vtNotUnderline}"
  Write-Information "${vtForegroundYellow}Usage: ${vtForegroundWhite}.\YamlCreate.ps1 [-PackageIdentifier <identifier>] [-PackageVersion <version>] [-Mode <1-5>] [-Settings] [-SkipPRCheck]"
  Write-Information "${vtDefault}"
  Invoke-CleanExit 0
}

# Ensure the settings file exists
Initialize-Folder -FolderPath $(Split-Path -Path $script:SettingsPath) | Out-Null
if (!(Test-Path $script:SettingsPath)) { '# See https://github.com/microsoft/winget-pkgs/tree/master/doc/tools/YamlCreate.md for a list of available settings' > $script:SettingsPath }

if ($Settings) {
  Invoke-Item -Path $script:SettingsPath
  Invoke-CleanExit 0
}

if (!$script:isInteractive) {
  Write-Error 'This tool cannot be run in a headless session. Please ensure your terminal or user session supports interactivity'
  Invoke-CleanExit -1
}

Initialize-ScriptRepository
#### End of Early Exiting Main-Functions

#### Set up script dependencies that may need to be downloaded
Initialize-Module -Name 'powershell-yaml' # Used for parsing YAML files
Initialize-Module -Name 'MSI' -Cmdlet @('Get-MSITable'; 'Get-MSIProperty') # Used for fetching MSI Properties
Initialize-Module -Name 'NtObjectManager' -Function @('Get-Win32ModuleResource'; 'Get-Win32ModuleManifest') # Used for checking installer type inno
Import-Module -Name 'YamlCreate' -Scope Global -Force -ErrorAction 'Stop' # Parent module that loads the rest of the modules required for the script
#### End of script dependencies

#### These variables are initialized late to prevent fetching file contents if -Help or -Settings was used

Write-Verbose "Loading Settings from ${script:SettingsPath}"
$script:UserSettings = ConvertFrom-Yaml -Yaml ($(Get-Content -Path $script:SettingsPath -Encoding 'UTF8') -join "`n")
$script:TestManifestsInSandbox = $script:UserSettings.TestManifestsInSandbox | Initialize-AlwaysNeverSetting
$script:SaveToTemporaryFolder = $script:UserSettings.SaveToTemporaryFolder | Initialize-AlwaysNeverSetting
$script:AutoSubmitPRs = $script:UserSettings.AutoSubmitPRs | Initialize-AlwaysNeverSetting
$script:ContinueWithExistingPRs = $script:UserSettings.ContinueWithExistingPRs | Initialize-AlwaysNeverSetting
$script:UseRedirectedUris = $script:UserSettings.UseRedirectedURL | Initialize-AlwaysNeverSetting
$script:HasSignedCLA = $script:UserSettings.SignedCLA -eq 'true'
$script:SuppressQuickUpdateWarning = $script:UserSettings.SuppressQuickUpdateWarning -eq 'true'
$script:RequireExplicitMenuing = $script:UserSettings.ExplicitMenuOptions -eq 'true'
$script:IdentifyBurnInstallers = $script:UserSettings.IdentifyBurnInstallers -eq 'true'
$script:DeveloperSettingsEnabled = $script:UserSettings.EnableDeveloperOptions -eq 'true'

# Schemas
# If SchemaVersion is not provided, the module will use the default version which is set in the module itself
Write-Verbose 'Fetching Manifest Schemas'
Initialize-VersionSchema -SchemaVersion $script:UserSettings.OverrideManifestVersion
Initialize-InstallerSchema -SchemaVersion $script:UserSettings.OverrideManifestVersion
Initialize-DefaultLocaleSchema -SchemaVersion $script:UserSettings.OverrideManifestVersion
Initialize-LocaleSchema -SchemaVersion $script:UserSettings.OverrideManifestVersion

# Variables used through the script
# These may or may not need to be initialized, but they are anyways just to be safe
$script:UserSelectedMode = $null
$script:ManifestsFolder = Get-ManifestsFolder
$script:ExecutionMode = $null
$script:PackageFolderExists = $false
$script:PackageVersionExists = $false
$script:SelectedManifest = @{
  'Identifier' = $PackageIdentifier
  'Version'    = $null
  'Path'       = $null
}

# Handle user selected mode
if ($PSBoundParameters.ContainsKey('Mode')) { $script:UserSelectedMode = [ScriptModes]::Parse([ScriptModes], $Mode, $true) }
if ($AutoUpgrade) { $script:UserSelectedMode = [ScriptModes]::AutoUpgrade }
# If the user selected mode is not set, prompt the user for a mode
if (-not $script:UserSelectedMode) {
  Write-Information @"
${vtForegroundBrightYellow}
Please select a mode:
  ${vtForegroundWhite}1. ${vtForegroundCyan}Create a new manifest
  ${vtForegroundWhite}2. ${vtForegroundCyan}Quick create a new version of an existing manifest
  ${vtForegroundWhite}3. ${vtForegroundCyan}Update the metadata of an existing manifest
  ${vtForegroundWhite}4. ${vtForegroundCyan}Add a new locale to an existing manifest
  ${vtForegroundWhite}5. ${vtForegroundCyan}Remove a manifest
  ${vtForegroundWhite}6. ${vtForegroundCyan}Move a package to a new identifier
  ${vtForegroundWhite}Q. ${vtForegroundRed}Any key to quit
${vtForegroundDefault}
"@
  # TODO: Implement the menuing system
  $key = Resolve-Keypress -ValidKeys $($Numeric1 + $Numeric2 + $Numeric3 + $Numeric4 + $Numeric5 + $Numeric6) -DefaultKey ([ConsoleKey]::Q) -UseStrict $script:RequireExplicitMenuing

  switch ($key) {
    { $_ -eq [ConsoleKey]::D1 -or $_ -eq [ConsoleKey]::NumPad1 } { $script:UserSelectedMode = [ScriptModes]::FullUpdate }
    { $_ -eq [ConsoleKey]::D2 -or $_ -eq [ConsoleKey]::NumPad2 } { $script:UserSelectedMode = [ScriptModes]::QuickUpdateVersion }
    { $_ -eq [ConsoleKey]::D3 -or $_ -eq [ConsoleKey]::NumPad3 } { $script:UserSelectedMode = [ScriptModes]::MetadataUpdate }
    { $_ -eq [ConsoleKey]::D4 -or $_ -eq [ConsoleKey]::NumPad4 } { $script:UserSelectedMode = [ScriptModes]::NewLocale }
    { $_ -eq [ConsoleKey]::D5 -or $_ -eq [ConsoleKey]::NumPad5 } { $script:UserSelectedMode = [ScriptModes]::RemoveManifest }
    { $_ -eq [ConsoleKey]::D6 -or $_ -eq [ConsoleKey]::NumPad6 } { $script:UserSelectedMode = [ScriptModes]::MoveManifests }
    default { Invoke-CleanExit 0 }
  }
}

# To determine the execution mode, we need to check if the manifest already exists, which we need the Identifier and Version for

# Check that the package identifier is valid
if (!(Test-PackageIdentifier -PackageIdentifier $PackageIdentifier -OutVariable ValidationResult).IsValid) {
  # If there was a validation error, print the error and request the package identifier, but only if the user provided an identifier
  if ($PackageIdentifier) { Write-Information "${vtForegroundRed}${validationResult}${vtForegroundDefault}" }
  # Requues the user to provide a valid package identifier
  $PackageIdentifier = Request-PackageIdentifier
}

# TODO: Normalize the package identifier to any segments already present in the manifests folder

# - If the package identifier is provided, check if it is a valid identifier
# - If the package identifier is not provided, request it until a valid identifier is provided

# Once the package identifier is provided, check if it already exists in the manifests folder

# Handle provided package version
# - If the package version is provided, check if it is a valid version
# - If the package version is not provided, request it until a valid version is provided

# Once the package version is provided, if the package identifier already exists, check if the version already exists

# Set Execution Mode based upon the user selected mode and whether or not the manifest already exists

# If the version already exists, load the existing manifest into memory
# If it is a singleton
# - Load the existing manifest into memory as a multi-manifest
# - Write the multi-manifest to the manifests folder
# - Remove the singleton manifest file

Invoke-CleanExit -1


