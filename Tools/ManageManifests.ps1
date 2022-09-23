#Requires -Version 5

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost',
    '',
    Justification = 'This script is not intended to have any outputs piped'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseApprovedVerbs',
    '',
    Justification = "'Validate' is only intended to be used as an internal verb, and is meant for script readability",
    Scope = 'Function',
    Target = 'Validate-*'
)]

Param
(
    [Parameter()] [string] $PackageIdentifier,
    [Parameter()] [string] $PackageVersion,
    [Parameter()] [int] $Mode,
    [Parameter(
        Mandatory = $false,
        ValueFromPipeline = $true
    )]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject] $InputObject,

    [switch] $Settings,
    [switch] $Help
)

# This section is run when the script is initially called. It is only run once
# This section should only execute when the script does not contain an input object,
# since this is where the requests for user input will be performed.

Begin {

    ########## CONSTANTS DEFINITIONS ###########
    #
    # This section contains definitions of all the constants used elsewhere in this script.
    # Any constants which are to be used in the process section must be defined here before
    # they will be available at the script level. The values here should be the same in
    # every execution of the script.
    #
    ############################################

    New-Variable -Name 'UpstreamUri' -Value 'https://github.com/microsoft/winget-pkgs.git' -Option Constant
    New-Variable -Name 'ToNatural' -Value { [regex]::Replace($_, '\d+', { $args[0].Value.PadLeft(20) }) } -Option Constant
    New-Variable -Name 'ScriptHeader' -Value '# Created with ManageManifests.ps1 ' -Option Constant
    New-Variable -Name 'ScriptVersion' -Value 'v3.0.0-alpha.1' -Option Constant
    New-Variable -Name 'ManifestVersion' -Value '1.1.0' -Option Constant
    New-Variable -Name 'PowershellMajorVersion' -Value $PSVersionTable.PSVersion.Major -Option constant
    New-Variable -Name 'Utf8NoBomEncoding' -Value (New-Object System.Text.UTF8Encoding $False) -Option Constant
    New-Variable -Name 'IsWindowsOS' -Value ([System.Environment]::OSVersion.Platform -match 'Win') -Option Constant
    New-Variable -Name 'ScriptSettingsFile' -Value (Join-Path -Path $(if ($IsWindowsOS) { $env:LOCALAPPDATA } else { $env:HOME + '/.config' } ) -ChildPath 'ManageManifests/Settings.yaml') -Option Constant
    New-Variable -Name 'ScriptLogsFolder' -Value (Join-Path -Path $(if ($IsWindowsOS) { $env:LOCALAPPDATA } else { $env:HOME + '/.config' } ) -ChildPath 'ManageManifests/Logs') -Option Constant
    New-Variable -Name 'GitIsInstalled' -Value ((Get-Command 'git' -ErrorAction SilentlyContinue) -is [System.Object]) -Option Constant
    New-Variable -Name 'GitCliIsInstalled' -Value ((Get-Command 'gh' -ErrorAction SilentlyContinue) -is [System.Object]) -Option Constant
    New-Variable -Name 'WingetIsInstalled' -Value ((Get-Command 'winget' -ErrorAction SilentlyContinue) -is [System.Object]) -Option Constant
    New-Variable -Name 'SandboxIsEnabled' -Value ((Get-Command 'WindowsSandbox' -ErrorAction SilentlyContinue) -is [System.Object]) -Option Constant
    New-Variable -Name 'ManifestsFolder' -Value $(if (Test-Path -Path "$PSScriptRoot\..\manifests") { (Resolve-Path "$PSScriptRoot\..\manifests").Path } else { (Resolve-Path '.\').Path }) -Option Constant
    New-Variable -Name 'IsDotSourced' -Value $($MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -eq '') -Option Constant

    New-Variable -Name 'ModeChoiceMenu' -Value $(
        '[
            [{"text": "Select Mode:","color": "DarkYellow"}],
            [{"text": "","color": "White"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "1","color": "White"},{"text": "] New Manifest or Package Version","color": "DarkCyan"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "2","color": "White"},{"text": "] Quick Update Package Version ","color": "DarkCyan"},{"text": "(Note: Must be used only when latest version''s metadata is complete)","color": "Green"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "3","color": "White"},{"text": "] Update Package Metadata","color": "DarkCyan"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "4","color": "White"},{"text": "] New Locale","color": "DarkCyan"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "5","color": "White"},{"text": "] Remove a manifest","color": "DarkCyan"}],
            [{"text": "  [","color": "DarkCyan"},{"text": "Q","color": "White"},{"text": "] ","color": "DarkCyan"},{"text": "Any key to quit","color": "Red"}],
            [{"text": "","color": "White"}]
        ]'| ConvertFrom-Json
    ) -Option Constant

    $PSDefaultParameterValues = @{ '*:Encoding' = 'UTF8' }
    $PSDefaultParameterValues['out-file:width'] = 2000
    $ofs = ', '


    ############# LIMITED FUNCTIONS ##############
    #
    # This section is for the few special behaviors where the script is actually not
    # intended to run or provide any update process
    #
    ##############################################

    # If the user has selected the 'help' switch, always show the help message
    if ($help) {
        Write-Host -ForegroundColor 'Green' 'For full documentation of the script, see https://github.com/microsoft/winget-pkgs/tree/master/doc/tools/YamlCreate.md'
        Write-Host -ForegroundColor 'Yellow' 'Usage: ' -NoNewline
        Write-Host -ForegroundColor 'White' '.\YamlCreate.ps1 [-PackageIdentifier <identifier>] [-PackageVersion <version>] [-Mode <1-5>] [-Settings] [-SkipPRCheck]'
        Write-Host
        exit
    }

    # If the user has selected the 'settings' switch, always show the help message
    if ($Settings) {
        Invoke-Item -Path $ScriptSettingsFile
        exit
    }

    # If the user has dot sourced the script, load all the functions but do not run the script
    if ($IsDotSourced) {
        Write-Host -ForegroundColor 'Yellow' 'The script was not called with an implicit source or has been dot sourced. The variables and functions have been loaded into memory, but the script cannot be run without implicit sourcing.'
    }

    ############# DEPENDENCIES ##############
    #
    # This section installs the dependencies of the script.
    # The reason this is done manually is to make it easier for first time contributors
    # to use this script. It is also important to keep in mind that there are significant
    # differences between Powershell 5 and Powershell Core (Powershell 7). Because of the
    # various use cases, any changes to this file must be tested on both versions.
    #
    ##########################################

    # Installs `powershell-yaml` as a dependency for parsing yaml content
    if (-not(Get-Module -ListAvailable -Name powershell-yaml)) {
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Install-Module -Name powershell-yaml -Force -Repository PSGallery -Scope CurrentUser
        } catch {
            # If there was an exception while installing powershell-yaml, pass it as an InternalException for further debugging
            throw [UnmetDependencyException]::new("'powershell-yaml' unable to be installed successfully", $_.Exception)
        } finally {
            # Double check that it was installed properly
            if (-not(Get-Module -ListAvailable -Name powershell-yaml)) {
                throw [UnmetDependencyException]::new("'powershell-yaml' is not found")
            }
        }
    }

    ########## CLASS DEFINITIONS ###########
    #
    # This section contains the definitions for custom classes which are used throughout
    # the script. These classes are important for controlling program flow as well as user
    # input. Classes should be used to reduce the number of function calls, where possible
    #
    ########################################

    # Error levels for the ReturnValue class
    Enum ErrorLevel {
        Undefined = -1
        Info = 0
        Warning = 1
        Error = 2
        Critical = 3
    }

    # Custom class for validation and error checking
    # `200` should be indicative of a success
    # `400` should be indicative of a bad request
    # `500` should be indicative of an internal error / other error
    Class ReturnValue {
        [int] $StatusCode
        [string] $Title
        [string] $Message
        [ErrorLevel] $Severity

        # Default Constructor
        ReturnValue() {
        }

        # Overload 1; Creates a return value with only a status code and no descriptors
        ReturnValue(
            [int]$statusCode
        ) {
            $this.StatusCode = $statusCode
            $this.Title = '-'
            $this.Message = '-'
            $this.Severity = -1
        }

        # Overload 2; Create a return value with all parameters defined
        ReturnValue(
            [int] $statusCode,
            [string] $title,
            [string] $message,
            [ErrorLevel] $severity
        ) {
            $this.StatusCode = $statusCode
            $this.Title = $title
            $this.Message = $message
            $this.Severity = $severity
        }

        # Static reference to a default success value
        [ReturnValue] static Success() {
            return [ReturnValue]::new(200, 'OK', 'The command completed successfully', 'Info')
        }

        # Static reference to a default internal error value
        [ReturnValue] static GenericError() {
            return [ReturnValue]::new(500, 'Internal Error', 'Value was not able to be saved successfully', 2)
        }

        # Static reference to a specific error relating to the pattern of user input
        [ReturnValue] static PatternError() {
            return [ReturnValue]::new(400, 'Invalid Pattern', 'The value entered does not match the pattern requirements defined in the manifest schema', 2)
        }

        # Static reference to a specific error relating to the length of user input
        [ReturnValue] static LengthError([int]$MinLength, [int]$MaxLength) {
            return [ReturnValue]::new(400, 'Invalid Length', "Length must be between $MinLength and $MaxLength characters", 2)
        }

        # Static reference to a specific error relating to the number of entries a user input
        [ReturnValue] static MaxItemsError([int]$MaxEntries) {
            return [ReturnValue]::new(400, 'Too many entries', "Number of entries must be less than or equal to $MaxEntries", 2)
        }

        # Returns the ReturnValue as a nicely formatted string
        [string] ToString() {
            return "[$($this.Severity)] ($($this.StatusCode)) $($this.Title) - $($this.Message)"
        }

        # Returns the ReturnValue as a nicely formatted string if the status code is not equal to 200
        [string] ErrorString() {
            if ($this.StatusCode -match '2[0-9]{2}') {
                return $null
            } else {
                return "[$($this.Severity)] $($this.Title) - $($this.Message)`n"
            }
        }
    }
    New-Variable -Name 'SuccessStatusCode' -Value ([ReturnValue]::Success().StatusCode) -Option Constant

    ########## FUNCTION DEFINITIONS ###########
    #
    # This section contains definitions of all the functions used elsewhere in this script.
    # Any functions which are to be used in the process section must be defined here before
    # they will be available to the script. Script variables should be avoided at all costs
    # due to the process function being able to perform parallell processes.
    #
    ###########################################
    Filter TrimString {
        $_.Trim()
    }
    Filter ToLower {
        [string]$_.ToLower()
    }
    Filter ToUpper {
        [string]$_.ToUpper()
    }
    Filter NoWhitespace {
        [string]$_ -replace '\s{1,}', '-'
    }

    Function Write-MulticolorOutput($OutputObject) {
        ForEach ($Line in $OutputObject) {
            ForEach ($Entry in $Line) {
                Write-Host -ForegroundColor "$($Entry.color)" $Entry.text -NoNewline
            }
            Write-Host
        }
    }

    Function Get-ItemMetadata {
        <#
        Inputs: Path to a file
        Outputs: A hashtable containting all of the file's populated metadata properties
        Usage: Get-ItemMetadata -FilePath <Path>
        #>
        Param (
            [Parameter(Mandatory = $true)] [string] $FilePath
        )
        try {
            $_MetaDataObject = [ordered] @{}
            $_FileInformation = (Get-Item $FilePath)
            $_ShellApplication = New-Object -ComObject Shell.Application
            $_ShellFolder = $_ShellApplication.Namespace($_FileInformation.Directory.FullName)
            $_ShellFile = $_ShellFolder.ParseName($_FileInformation.Name)
            $_MetaDataProperties = [ordered] @{}
            0..400 | ForEach-Object -Process {
                $_DataValue = $_ShellFolder.GetDetailsOf($null, $_)
                $_PropertyValue = (Get-Culture).TextInfo.ToTitleCase($_DataValue.Trim()).Replace(' ', '')
                if ($_PropertyValue -ne '') {
                    $_MetaDataProperties["$_"] = $_PropertyValue
                }
            }
            foreach ($_Key in $_MetaDataProperties.Keys) {
                $_Property = $_MetaDataProperties[$_Key]
                $_Value = $_ShellFolder.GetDetailsOf($_ShellFile, [int] $_Key)
                if ($_Property -in 'Attributes', 'Folder', 'Type', 'SpaceFree', 'TotalSize', 'SpaceUsed') {
                    continue
                }
                If (($null -ne $_Value) -and ($_Value -ne '')) {
                    $_MetaDataObject["$_Property"] = $_Value
                }
            }
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($_ShellFile)
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($_ShellFolder)
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($_ShellApplication)
            [void][System.GC]::Collect()
            [void][System.GC]::WaitForPendingFinalizers()
            return $_MetaDataObject
        } catch {
            Write-Error -Message $_.ToString()
            break
        }
    }

    Function Initialize-ScriptSettings {
        if (!(Test-Path $ScriptSettingsFile)) { New-Item -Path $ScriptSettingsFile -ItemType File -Force | Out-Null }
        return (ConvertFrom-Yaml -Yaml $(Get-Content -Path $ScriptSettingsFile -Raw))
    }

    Function Initialize-ScriptLogging {
        if (!$ScriptSettings) { return @{ EnableLogging = $false; LogFile = $null } }
        if ($ScriptSettings.DisableLogging -eq $true) { return @{ EnableLogging = $false; LogFile = $null } }
        if (!(Test-Path $ScriptLogsFolder)) { New-Item -Path $ScriptLogsFolder -ItemType Directory -Force }
        $_LogPath = Join-Path -Path $ScriptLogsFolder -ChildPath "$((New-Guid).ToString('N')).log"
        New-Item -Path $_LogPath -ItemType File -Force | Out-Null
        return @{ EnableLogging = $true; LogFile = $_LogPath }
    }

    Filter Out-Log {
        if ($ScriptLogging.LogFile) { $_ | Out-File -FilePath $ScriptLogging.LogFile -Append }
    }

    Function Read-KeyPress {
        do {
            $keyInfo = [Console]::ReadKey($false)
        } until ($keyInfo.Key)

        return $keyInfo.Key
    }

    Function Validate-PackageIdentifier {
        Param (
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string] $PackageIdentifier
        )
        if ([string]::IsNullOrEmpty($PackageIdentifier)) { return [ReturnValue]::new(204, 'No Content', 'The package identifier has no value', 0) }
        if (
            ($PackageIdentifier.Length -gt $ValidationPatterns.IdentifierMaxLength) -or
            ($PackageIdentifier.Length -lt 4)
        ) { return [ReturnValue]::LengthError(4, $ValidationPatterns.IdentifierMaxLength) }
        if ($PackageIdentifier -notmatch $ValidationPatterns.PackageIdentifier) { return [ReturnValue]::PatternError() }
        return [ReturnValue]::Success()
    }

    Function Request-PackageIdentifier {
        Param (
            [Parameter(Mandatory = $false)]
            [AllowEmptyString()]
            [string] $PackageIdentifier
        )
        $_ValidationResult = Validate-PackageIdentifier $PackageIdentifier
        while ($_ValidationResult.StatusCode -ne $SuccessStatusCode) {
            Write-Host -ForegroundColor 'Red' $_ValidationResult.ErrorString()
            Write-Host -ForegroundColor 'Green' -Object '[Required] Enter the Package Identifier, in the following format <Publisher shortname.Application shortname>. For example: Microsoft.Excel'
            $PackageIdentifier = Read-Host -Prompt 'PackageIdentifier' | TrimString
            $_ValidationResult = Validate-PackageIdentifier -PackageIdentifier $PackageIdentifier
        }
        return $PackageIdentifier
    }

    Function Validate-PackageVersion {
        Param (
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string] $PackageVersion
        )
        if ([string]::IsNullOrWhiteSpace($PackageVersion)) { return [ReturnValue]::new(204, 'No Content', 'The package version has no value', 0) }
        if ($PackageVersion.Length -gt $ValidationPatterns.VersionMaxLength) { return [ReturnValue]::LengthError(1, $ValidationPatterns.VersionMaxLength) }
        if ($PackageVersion -notmatch $ValidationPatterns.PackageVersion) { return [ReturnValue]::PatternError() }
        return [ReturnValue]::Success()
    }

    Function Request-PackageVersion {
        Param (
            [Parameter(Mandatory = $false)]
            [AllowEmptyString()]
            [string] $PackageVersion
        )
        $_ValidationResult = Validate-PackageVersion $PackageVersion
        while ($_ValidationResult.StatusCode -ne $SuccessStatusCode) {
            Write-Host -ForegroundColor 'Red' $_ValidationResult.ErrorString()
            Write-Host -ForegroundColor 'Green' -Object '[Required] Enter the version. for example: 1.33.7'
            $PackageVersion = Read-Host -Prompt 'Version' | TrimString
            $_ValidationResult = Validate-PackageVersion $PackageVersion
        }
        return $PackageVersion
    }

    Function Validate-InstallerUrl {
        Param (
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string] $Url
        )
        if ([string]::IsNullOrWhiteSpace($Url)) { return [ReturnValue]::new(204, 'No Content', 'The URL must not be empty', 0) }
        if ($Url.Length -gt $ValidationPatterns.InstallerUrlMaxLength) { return [ReturnValue]::LengthError(1, $ValidationPatterns.InstallerUrlMaxLength) }
        if ($Url -notmatch $ValidationPatterns.InstallerUrl) { return [ReturnValue]::PatternError() }
        return [ReturnValue]::Success()
    }

    Function Request-InstallerUrl {
        Param (
            [Parameter(Mandatory = $false)]
            [AllowEmptyString()]
            [string] $Url
        )
        $_ValidationResult = Validate-InstallerUrl $Url
        while ($_ValidationResult.StatusCode -ne $SuccessStatusCode) {
            Write-Host -ForegroundColor 'Red' $_ValidationResult.ErrorString()
            Write-Host -ForegroundColor 'Green' -Object '[Required] Enter the download url to the installer.'
            $Url = Read-Host -Prompt 'Url' | TrimString
            $_ValidationResult = Validate-InstallerUrl $Url
        }
        return Get-UrlResponse $Url
    }

    Function Get-PackageFolder {
        Param (
            [Parameter(Mandatory = $true)]
            [string] $PackageIdentifier
        )
        return "$ManifestsFolder\$($PackageIdentifier.ToLower().Chars(0))\$($PackageIdentifier.Replace('.', '\'))"
    }

    Function Get-PackageStructure {
        Param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageIdentifier
        )
        $_PackageFolder = Get-PackageFolder -PackageIdentifier $PackageIdentifier
        if (!(Test-Path $_PackageFolder)) { return $null }
        $_ManifestFiles = (Get-ChildItem -Path $_PackageFolder -Recurse -Depth 1 -File -Filter '*.yaml' -ErrorAction SilentlyContinue).FullName
        $_PackageVersions = $(
            if ($null -ne $_ManifestFiles) {
                @(Split-Path (Split-Path $_ManifestFiles) -Leaf | Sort-Object $ToNatural | Select-Object -Unique)
            } else { $null }
        )
        $_PackageFiles = Get-ChildItem -Path $_PackageFolder
        $_ValidationFile = $(if ('.validation' -cin $_PackageFiles.Name) { $_PackageFiles.Where({ $_.Name -ceq '.validation' }) })
        return @{
            PackageFolder   = $_PackageFolder
            PackageVersions = $_PackageVersions
            ValidationFile  = $_ValidationFile
            SubPackages     = (Get-ChildItem -Path $_PackageFolder -Directory).Where({ $_.Name -cnotin $_PackageVersions }).Name
        }
    }

    Function Get-VersionStructure {
        Param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageIdentifier,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageVersion
        )
        $_PackageStructure = Get-PackageStructure -PackageIdentifier $PackageIdentifier
        if ($PackageVersion -cnotin $_PackageStructure.PackageVersions) { return $null }
        $_VersionFolder = Join-Path -Path $_PackageStructure.PackageFolder -ChildPath $PackageVersion
        $_VersionFiles = Get-ChildItem $_VersionFolder
        $_VersionManifest = $(if ("$PackageIdentifier.yaml" -cin $_VersionFiles.Name) { $_VersionFiles.Where({ $_.Name -ceq "$PackageIdentifier.yaml" }) })
        $_InstallerManifest = $(if ("$PackageIdentifier.installer.yaml" -cin $_VersionFiles.Name) { $_VersionFiles.Where({ $_.Name -ceq "$PackageIdentifier.installer.yaml" }) })
        $_ValidationFile = $(if ('.validation' -cin $_VersionFiles.Name) { $_VersionFiles.Where({ $_.Name -ceq '.validation' }) })
        if (!$_ValidationFile) { if ($_PackageStructure.ValidationFile) { $_ValidationFile = $_PackageStructure.ValidationFile } }
        $_LocaleManifests = @($($_VersionFiles.Where({ $_.Name -cnotin @($_VersionManifest.Name; $_InstallerManifest.Name; $_ValidationFile.Name) })))
        return @{
            PackageFolder     = $_PackageStructure.PackageFolder
            VersionFolder     = $_VersionFolder
            VersionManifest   = $_VersionManifest
            InstallerManifest = $_InstallerManifest
            LocaleManifests   = $_LocaleManifests
            ValidationFile    = $_ValidationFile
            ManifestType      = $(
                if ($null -eq $_InstallerManifest -and $_LocaleManifests.Count -eq 0 -and $null -ne $_VersionManifest) { 'Singleton' }
                elseif ($null -ne $_InstallerManifest -and $_LocaleManifests.Count -gt 0 -and $null -ne $_VersionManifest) { 'MultiManifest' }
                else { 'Unknown' }
            )
        }
    }

    Function Validate-PackageVersionExists {
        Param (
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string] $PackageIdentifier,
            [Parameter(Mandatory = $true)]
            [AllowEmptyString()]
            [string] $PackageVersion
        )
        if ([string]::IsNullOrEmpty($PackageIdentifier)) { return [ReturnValue]::new(204, 'No Content', 'The package identifier has no value', 0) }
        if ($null -ne (Get-VersionStructure $PackageIdentifier $PackageVersion)) { return [ReturnValue]::Success() }
        else { return [ReturnValue]::new(404, 'Version not found', 'The version does not exist for that package', 2) }
    }

    Function Get-UrlResponse {
        Param
        (
            [Parameter(Mandatory = $true, Position = 0)]
            [string] $URL
        )
        try {
            $HTTP_Request = [System.Net.WebRequest]::Create($URL)
            $HTTP_Request.UserAgent = 'Microsoft-Delivery-Optimization/10.1'
            $HTTP_Response = $HTTP_Request.GetResponse()
            $ResponseUri = $HTTP_Response.ResponseUri
            $AbsoluteUrl = $HTTP_Response.ResponseUri.AbsoluteUri
            $HTTP_Status = [int]$HTTP_Response.StatusCode
            $ResponseLength = $HTTP_Response.ContentLength
            $Headers = @{}; $HTTP_Response.Headers.ForEach({ $Headers[$_] = $Http_Response.Headers[$_] })
        } catch {
            $HTTP_Status = 404
        }
        If ($null -eq $HTTP_Response) { $HTTP_Status = 404 }
        Else { $HTTP_Response.Close() }
        return @{
            Url           = $URL
            ResponseUrl   = $AbsoluteUrl
            ResponseCode  = $HTTP_Status
            ContentLength = $ResponseLength
            Headers       = $Headers
            Response      = $ResponseUri
        }
    }

    Function Get-UrlResponseFilename($UrlResponse, $AlternateName) {
        if ($UrlResponse.Headers.Keys -contains 'Content-Disposition') {
            [string]$_Filename = $UrlResponse.Headers['Content-Disposition'].Split(';').Trim().Where({ $_ -match 'filename=' }).Split('=')[1]
        }
        if ([string]::IsNullOrWhiteSpace($_Filename)) {
            #Try getting the extension from the ResponseUrl
            $_Extension = Get-UrlFileExtension $UrlResponse.ResponseUrl
            if ([string]::IsNullOrWhiteSpace($_Extension)) { $_Extension = Get-UrlFileExtension $UrlResponse.Url }
            if ([string]::IsNullOrWhiteSpace($_Extension)) { $_Extension = '.winget-tmp' }
            $_Filename = "$AlternateName$_Extension"
        }
        if (-1 -ne ($_FileName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()))) { return (New-TemporaryFile).Name }
        return $_Filename
    }

    Function Get-InstallerFile($UrlResponse, $AlternateName) {
        $ProgressPreference = 'Continue'
        $_Filename = Get-UrlResponseFilename $UrlResponse $AlternateName
        $_FilePath = Join-Path -Path $env:TEMP -ChildPath $_FileName
        $_File = Invoke-WebClientDownload $UrlResponse $_FilePath
        if ($null -eq $_File) { $_File = Invoke-ResponseStreamDownload $UrlResponse $_FilePath }
        $ProgressPreference = 'SilentlyContinue'
        if ($null -eq $_File) {
            throw [System.Net.WebException]::new('The file could not be downloaded. Try running the script again', $_.Exception)
        }
        return $_File
    }

    Function Invoke-ResponseStreamDownload($UrlResponse, $FilePath) {
        try {
            $_Download = Invoke-WebRequest -Uri $UrlResponse.Url
            $_FileStream = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Create)
            $_FileStream.Write($_Download.Content, 0 , $_Download.RawContentLength)
            $_FileStream.Close()
            $_File = [System.IO.FileInfo]::new($FilePath)
        } catch {
            Write-Host -ForegroundColor 'Red' 'The file could not be downloaded using the response stream'
            $_File = $null
        }
        return $_File
    }

    Function Invoke-WebClientDownload($UrlResponse, $FilePath) {
        $_WebClient = [System.Net.WebClient]::new()
        $_WebClient.Headers.Add('User-Agent', 'Microsoft-Delivery-Optimization/10.1')
        if ($PowershellMajorVersion -lt 6) { $_WebClient.Proxy = [System.Net.WebProxy]::GetDefaultProxy() }
        try {
            $_WebClient.DownloadFile($UrlResponse.Url, $FilePath)
            $_File = [System.IO.FileInfo]::new($FilePath)
        } catch {
            Write-Host -ForegroundColor 'Yellow' 'The file could not be downloaded using the standard web client'
            $_File = $null
        } finally {
            $_WebClient.Dispose()
        }
        return $_File
    }

    Function Get-UrlFileExtension($Url) {
        $_UrlResponse = Get-UrlResponse $Url
        if ([System.IO.Path]::HasExtension($_UrlResponse.Response.AbsolutePath)) { return [System.IO.Path]::GetExtension($_UrlResponse.Response.AbsolutePath) }
        if ([System.IO.Path]::HasExtension($Url)) { return [System.IO.Path]::GetExtension($Url) }
        $_SplitPath = (@($_UrlResponse.Response.AbsolutePath) -split '/|\?|\&').Where({ [System.IO.Path]::HasExtension($_) })[0]
        if ([System.IO.Path]::HasExtension($_SplitPath)) { return [System.IO.Path]::GetExtension($_SplitPath) }
        return $null
    }

    function Get-Property ($Object, $PropertyName, [object[]]$ArgumentList) {
        return $Object.GetType().InvokeMember($PropertyName, 'Public, Instance, GetProperty', $null, $Object, $ArgumentList)
    }

    Function Get-MsiDatabase {
        Param
        (
            [Parameter(Mandatory = $true)]
            [string] $FilePath
        )
        $windowsInstaller = New-Object -com WindowsInstaller.Installer
        $MSI = $windowsInstaller.OpenDatabase($FilePath, 0)
        $_TablesView = $MSI.OpenView('select * from _Tables')
        $_TablesView.Execute()
        $_Database = @{}
        do {
            $_Table = $_TablesView.Fetch()
            if ($_Table) {
                $_TableName = Get-Property $_Table StringData 1
                $_Database["$_TableName"] = @{}
            }
        } while ($_Table)
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($_TablesView)
        foreach ($_Table in $_Database.Keys) {
            $_ItemView = $MSI.OpenView("select * from $_Table")
            $_ItemView.Execute()
            do {
                $_Item = $_ItemView.Fetch()
                if ($_Item) {
                    $_ItemValue = $null
                    $_ItemName = Get-Property $_Item StringData 1
                    if ($_Table -eq 'Property') { $_ItemValue = Get-Property $_Item StringData 2 -ErrorAction SilentlyContinue }
                    $_Database.$_Table["$_ItemName"] = $_ItemValue
                }
            } while ($_Item)
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($_ItemView)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($MSI)
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($windowsInstaller)
        return $_Database
    }

    Function Test-IsWix {
        Param
        (
            [Parameter(Mandatory = $true)]
            [object] $Database,
            [Parameter(Mandatory = $true)]
            [object] $MetaDataObject
        )
        # If any of the table names match wix
        if ($Database.Keys -match 'wix') { return $true }
        # If any of the keys in any of the tables match wix
        if ($Database.Values.Keys.Where({ $_ -match 'wix' })) { return $true }
        # If any of the values of any of the keys in any of the tables match wix
        if ($Database.Values.Values.Where({ $_ -match 'wix' })) { return $true }
        # If the CreatedBy value matches wix
        if ($MetaDataObject.ProgramName -match 'wix') { return $true }
        # If the CreatedBy value matches xml
        if ($MetaDataObject.ProgramName -match 'xml') { return $true }
        return $false
    }

    Function Remove-ManifestVersion {
        [CmdletBinding(SupportsShouldProcess)]
        Param(
            [Parameter(Mandatory = $true, Position = 1)]
            [string] $PathToVersion
        )
        # Remove the manifest, and then any parent folders so long as the parent folders are empty
        do {
            Remove-Item -Path $PathToVersion -Recurse -Force
            $PathToVersion = Split-Path $PathToVersion
        } while (@(Get-ChildItem $PathToVersion).Count -eq 0)
    }

    Function Initialize-GitUpstream {
        if ($GitIsInstalled) {
            $_Remotes = git remote
            if ($_Remotes -notcontains 'upstream') { git remote add upstream $UpstreamUri }
            elseif ((git remote get-url upstream) -ne $UpstreamUri) { return $False }
        } else { return $False }
        return $True
    }

    Function Invoke-KeypressMenu($MenuObject) {
        Write-Host
        Write-Host -ForegroundColor 'Yellow' $MenuObject.Prompt
        if (![string]::IsNullOrWhiteSpace($MenuObject.HelpText)) { Write-Host -ForegroundColor $(if (![string]::IsNullOrWhiteSpace($MenuObject.HelpTextColor)) { $MenuObject.HelpTextColor } else { 'Blue' }) $MenuObject.HelpText }
        foreach ($entry in $MenuObject.Entries) {
            $_isDefault = $entry.StartsWith('*')
            if ($_isDefault) {
                $_entry = '  ' + $entry.Substring(1)
                $_color = 'Green'
            } else {
                $_entry = '  ' + $entry
                $_color = 'White'
            }
            Write-Host -ForegroundColor $_color $_entry
        }
        Write-Host
        if (![string]::IsNullOrWhiteSpace($MenuObject.DefaultString)) { Write-Host -NoNewline "Enter Choice (default is '$($MenuObject.DefaultString)'): " }
        else {
            Write-Host -NoNewline 'Enter Choice ('
            Write-Host -NoNewline -ForegroundColor 'Green' 'Green'
            Write-Host -NoNewline ' is default): '
        }
        $_Key = Read-KeyPress
        Write-Host
        return $_Key
    }

    Function Request-PRSubmission($AdditionalInfo) {
        $_PRSubmissionContent = @{
            AutoSubmit = $false
            PRBody     = $null
        }
        if (!$GitCliIsInstalled -or !$GitIsInstalled) { return $_PRSubmissionContent }
        switch ($ScriptSettings.PRSubmission.AutoSubmit) {
            'Always' { $_PRSubmissionContent['AutoSubmit'] = $true }
            'Never' { $_PRSubmissionContent['AutoSubmit'] = $false }
            # If the setting is not defined, ask the user
            Default {
                switch (Invoke-KeypressMenu (
                        @{
                            Prompt        = 'Do you want to submit your PR now?'
                            Entries       = @('*[Y] Yes'; '[N] No')
                            DefaultString = 'Y'
                        })
                ) {
                    'Y' { $_PRSubmissionContent['AutoSubmit'] = $true }
                    'N' { $_PRSubmissionContent['AutoSubmit'] = $false }
                    default { $_PRSubmissionContent['AutoSubmit'] = $true }
                }
            }
        }
        if ($_PRSubmissionContent.AutoSubmit -eq $false) { return $_PRSubmissionContent }
        $_PrSubmissionContent['PRBody'] = Request-PRBodyText($AdditionalInfo)
        return $_PRSubmissionContent
    }

    Function Request-PRBodyText($AdditionalInfo) {
        $_Text = @()
        $_Template = Get-PRTemplate
        if ($_Template) {
            ForEach ($_Line in ($_Template | Where-Object { $_ -like '-*[ ]*' })) {
                $_showMenu = $true
                switch -Wildcard ($_Line) {
                    '*CLA*' {
                        if ($ScriptSettings.PRSubmission.SignedCLA -eq 'always') {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.SignedCLA -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = 'Have you signed the Contributor License Agreement (CLA)?'
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = 'Reference Link: https://cla.opensource.microsoft.com/microsoft/winget-pkgs'
                                HelpTextColor = ''
                                DefaultString = 'N'
                            }
                        }
                    }
                    '*open *pull requests*' {
                        if ($ScriptSettings.PRSubmission.CheckedOpenPRs -eq 'always') {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.CheckedOpenPRs -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = "Have you checked that there aren't other open pull requests for the same manifest update/change?"
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = 'Reference Link: https://github.com/microsoft/winget-pkgs/pulls'
                                HelpTextColor = ''
                                DefaultString = 'N'
                            }
                        }
                    }
                    '*winget validate*' {
                        if ($ScriptSettings.PRSubmission.Validated -eq 'always' -or $AdditionalInfo.Validated -eq $true) {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.Validated -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = "Have you validated your manifest locally with 'winget validate --manifest <path>'?"
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = 'Automatic manifest validation failed. Check your manifest and try again'
                                HelpTextColor = 'Red'
                                DefaultString = 'N'
                            }
                        }
                    }
                    '*tested your manifest*' {
                        if ($ScriptSettings.PRSubmission.Tested -eq 'always' -or $AdditionalInfo.Tested -eq $true) {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.Tested -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = "Have you tested your manifest locally with 'winget install --manifest <path>'?"
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = 'You did not test your Manifest in Windows Sandbox previously.'
                                HelpTextColor = 'Red'
                                DefaultString = 'N'
                            }
                        }
                    }
                    '*schema*' {
                        if ($ScriptSettings.PRSubmission.SchemaConformation -eq 'always') {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.SchemaConformation -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = 'Does your manifest conform to the 1.0 schema?'
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = 'Reference Link: https://github.com/microsoft/winget-cli/blob/master/doc/ManifestSpecv1.0.md'
                                HelpTextColor = ''
                                DefaultString = 'N'
                            }
                        }
                    }
                    default {
                        if ($ScriptSettings.PRSubmission.OtherContent -eq 'always') {
                            $_Text += @($_line.Replace('[ ]', '[X]'))
                            $_showMenu = $false
                        } elseif ($ScriptSettings.PRSubmission.OtherContent -eq 'never') {
                            $_Text += @($_line)
                            $_showMenu = $false
                        } else {
                            $_Menu = @{
                                Prompt        = $_line.TrimStart('- [ ]')
                                Entries       = @('[Y] Yes'; '*[N] No')
                                HelpText      = ''
                                HelpTextColor = ''
                                DefaultString = 'N'
                            }
                        }
                    }
                }
                if ($_showMenu) {
                    switch ( Invoke-KeypressMenu $_Menu) {
                        'Y' { $_Text += @($_line.Replace('[ ]', '[X]')) }
                        default { $_Text += @($_line) }
                    }
                }
            }
        } else {
            Write-Host
            Write-Host -ForegroundColor 'Green' 'No PR Template was found. Please enter text for the body of your PR'
            $_InputText = Read-Host -Prompt 'PR Content' | TrimString
            if ([string]::IsNullOrWhiteSpace($_InputText)) { $_InputText = 'null' }
            $_Text = @($_InputText)
        }
        # TODO Get Linked Issues
        return $_Text
    }

    Function Get-PRTemplate {
        if (Test-Path -Path "$PSScriptRoot\..\.github\PULL_REQUEST_TEMPLATE.md") { return (Get-Content "$PSScriptRoot\..\.github\PULL_REQUEST_TEMPLATE.md") }
        return $null
    }

    Function Write-NewBranch {
        Param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $PackageIdentifier,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $CommitMessage
        )
        if (!$GitIsInstalled) { return $false }
        if (!(Initialize-GitUpstream)) { return $false }
        git fetch upstream master --quiet
        git switch -d upstream/master
        if ($LASTEXITCODE -eq '0') {
            $_BranchName = 'autogenerated/' + $PackageIdentifier + '/' + (New-Guid).ToString('D')
            git add 'manifests/*'
            git commit -m $CommitMessage --quiet
            git switch -c $_BranchName --quiet
            git push --set-upstream origin $_BranchName --quiet
        } else { return $false }
    }

    Function Import-YamlFile($Path) {
        return ConvertFrom-Yaml -Yaml ($(Get-Content -Path $Path -Encoding UTF8) -join "`n") -Ordered
    }

    Function Expand-InstallerRootItems($InstallerManifest) {
        $_KeysToMove = $InstallerEntryProperties | Where-Object { $_ -in $InstallerProperties } | Where-Object { $_ -in $InstallerManifest.Keys }
        foreach ($_Key in $_KeysToMove) {
            switch ($_Key) {
                # If the key is installer switches, it needs to be handled separately
                'InstallerSwitches' {
                    $_ExistingSwitches = $InstallerManifest.$_Key.Keys
                    foreach ($_Switch in $_ExistingSwitches) {
                        foreach ($_Installer in $InstallerManifest.Installers) {
                            # If the InstallerSwitches key doesn't exist, we need to create it
                            if ($_Key -notin $_Installer.Keys) { $_Installer[$_Key] = @{} }
                            if ($_Switch -notin $_Installer.$_Key.Keys) { $_Installer.$_Key[$_Switch] = $InstallerManifest.$_Key.$_Switch }
                        }
                        $_InstallerManifest.$_Key.Remove($_Switch)
                    }
                    $_InstallerManifest.Remove($_Key)
                }
                default {
                    foreach ($_Installer in $InstallerManifest.Installers) {
                        if ($_Key -notin $_Installer.Keys) { $_Installer[$_Key] = $InstallerManifest.$_Key }
                    }
                    $InstallerManifest.Remove($_Key)
                }
            }
        }
        return $InstallerManifest
    }

    Function Import-SingletonManifest($VersionStructure) {
        $_OriginalManifest = Import-YamlFile $VersionStructure.VersionManifest.FullName
        # Set up empty manifest structure for conversion
        $_VersionManifest = @{}
        $_defaultLocaleManifest = @{}
        $_InstallerManifest = @{}
        # Parse version keys to version manifest
        foreach ($_Key in $($_OriginalManifest.Keys | Where-Object { $_ -in $VersionProperties })) {
            $_VersionManifest[$_Key] = $_OriginalManifest.$_Key
            $_VersionManifest['ManifestType'] = 'version'
            $_VersionManifest['ManifestVersion'] = $ManifestVersion
        }
        # Parse defaultLocale keys to defaultLocale manifest
        foreach ($_Key in $($_OriginalManifest.Keys | Where-Object { $_ -in $defaultLocaleProperties })) {
            $_defaultLocaleManifest[$_Key] = $_OriginalManifest.$_Key
            $_defaultLocaleManifest['ManifestType'] = 'defaultLocale'
            $_defaultLocaleManifest['ManifestVersion'] = $ManifestVersion
        }
        # Parse installer keys to installer manifest
        foreach ($_Key in $($_OriginalManifest.Keys | Where-Object { $_ -in $InstallerProperties })) {
            $_InstallerManifest[$_Key] = $_OriginalManifest.$_Key
            $_InstallerManifest['ManifestType'] = 'installer'
            $_InstallerManifest['ManifestVersion'] = $ManifestVersion
        }
        $_InstallerManifest = Expand-InstallerRootItems $_InstallerManifest

        return @{
            Installer     = $_InstallerManifest
            defaultLocale = $_defaultLocaleManifest
            Version       = $_VersionManifest
            Locales       = @{}
        }
    }

    Function Import-MultiManifest($VersionStructure) {
        $_VersionManifest = Import-YamlFile $VersionStructure.VersionManifest.FullName
        $_InstallerManifest = Import-YamlFile $VersionStructure.InstallerManifest.FullName
        $_LocaleManifests = @{}
        $_defaultLocaleManifest = @{}
        foreach ($_Manifest in $VersionStructure.LocaleManifests) {
            $_Content = Import-YamlFile $_Manifest.FullName
            $_Locale = $_Content.PackageLocale
            $_Content.ManifestVersion = $ManifestVersion
            if ($_Content.ManifestType -eq 'defaultLocale') { $_defaultLocaleManifest = $_Content }
            else { $_LocaleManifests[$_Locale] = $_Content }
        }
        $_InstallerManifest = Expand-InstallerRootItems $_InstallerManifest
        return @{
            Installer     = $_InstallerManifest
            defaultLocale = $_defaultLocaleManifest
            Version       = $_VersionManifest
            Locales       = $_LocaleManifests
        }
    }

    Function Validate-InputObject($InputObject) {
        if ($InputObject.Keys -notcontains 'PackageIdentifier') { return [ReturnValue]::new(400, 'Missing Data', 'PackageIdentifier is required', 2) }
        if ($InputObject.Keys -notcontains 'PackageVersion') { return [ReturnValue]::new(400, 'Missing Data', 'PackageVersion is required', 2) }
        if ($InputObject.Keys -notcontains 'Action') { return [ReturnValue]::new(400, 'Missing Data', 'Action is required', 2) }
        if ($InputObject.Keys -notcontains 'PullRequest') { return [ReturnValue]::new(400, 'Missing Data', 'PullRequest is required', 2) }
        if ($InputObject.PullRequest.Keys -notcontains 'AutoSubmit') { return [ReturnValue]::new(400, 'Missing Data', 'PullRequest.AutoSubmit is required', 2) }
        if ($InputObject.PullRequest.AutoSubmit -eq $true) {
            if ($InputObject.PullRequest.Keys -notcontains 'PRBody') { return [ReturnValue]::new(400, 'Missing Data', 'PullRequest.PRBody is required', 2) }
        }
        switch ($InputObject.Action) {
            'Finalize' {
                if ($InputObject.Keys -notcontains 'DoValidation') { return [ReturnValue]::new(400, 'Missing Data', 'DoValidation is required', 2) }
                if ($InputObject.Keys -notcontains 'DoSandboxTest') { return [ReturnValue]::new(400, 'Missing Data', 'DoSandboxTest is required', 2) }
                if ($InputObject.PullRequest.Keys -notcontains 'CommitType') { return [ReturnValue]::new(400, 'Missing Data', 'PullRequest.CommitType is required', 2) }
            }
            'Delete' {
                $_VersionStructure = Get-VersionStructure $InputObject.PackageIdentifier $InputObject.PackageVersion
                if ($null -eq $_VersionStructure) { return [ReturnValue]::new(400, 'Bad Request', 'The package version does not exist', 2) }
                if ($_VersionStructure.ValidationFile) { return [ReturnValue]::new(403, 'Forbidden', 'The package may be effected by a validation file and must be removed manually', 2) }
            }
            'Auto' {
                #     $_VersionStructure = Get-VersionStructure $InputObject.PackageIdentifier $InputObject.PackageVersion
                #     if ($null -eq $_VersionStructure) { return [ReturnValue]::new(400, 'Bad Request', 'The package version does not exist', 2) }
            }
            default { return [ReturnValue]::new(400, 'Unsupported', "$($InputObject.Action) is not a valid action type", 2) }
        }
        return [ReturnValue]::Success()
    }

    ########## VARIABLE DEFINITIONS ###########
    #
    # This section contains definitions of all the variables used elsewhere in this script.
    # Any variables which are to be used in the process section must be defined here before
    # they will be available at the script level. The values here should be constants, since
    # they will remain the same through every execution of the process block. The variables
    # here differ from the constants definitions because these may change unexpectedly.
    #
    ###########################################

    # Fetch Schema data from github for entry validation, key ordering, and automatic commenting
    try {
        $ProgressPreference = 'SilentlyContinue'
        New-Variable -Name 'LocaleSchema' -Value @(Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$ManifestVersion/manifest.locale.$ManifestVersion.json" -UseBasicParsing | ConvertFrom-Json) -Option Constant
        New-Variable -Name 'LocaleProperties' -Value (ConvertTo-Yaml $LocaleSchema.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'defaultLocaleSchema' -Value @(Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$ManifestVersion/manifest.defaultLocale.$ManifestVersion.json" -UseBasicParsing | ConvertFrom-Json) -Option Constant
        New-Variable -Name 'defaultLocaleProperties' -Value (ConvertTo-Yaml $defaultLocaleSchema.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'VersionSchema' -Value @(Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$ManifestVersion/manifest.version.$ManifestVersion.json" -UseBasicParsing | ConvertFrom-Json) -Option Constant
        New-Variable -Name 'VersionProperties' -Value (ConvertTo-Yaml $VersionSchema.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'InstallerSchema' -Value @(Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$ManifestVersion/manifest.installer.$ManifestVersion.json" -UseBasicParsing | ConvertFrom-Json) -Option Constant
        New-Variable -Name 'InstallerProperties' -Value (ConvertTo-Yaml $InstallerSchema.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'InstallerSwitchProperties' -Value (ConvertTo-Yaml $InstallerSchema.definitions.InstallerSwitches.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'InstallerEntryProperties' -Value (ConvertTo-Yaml $InstallerSchema.definitions.Installer.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
        New-Variable -Name 'InstallerDependencyProperties' -Value (ConvertTo-Yaml $InstallerSchema.definitions.Dependencies.properties | ConvertFrom-Yaml -Ordered).Keys -Option Constant
    } catch {
        throw [System.Net.WebException]::new('Manifest schemas could not be downloaded. Try running the script again', $_.Exception)
    }
    # Various patterns used in validation to simplify the validation logic
    New-Variable -Name 'ValidationPatterns' -Value (
        @{
            PackageIdentifier         = $VersionSchema.properties.PackageIdentifier.pattern
            IdentifierMaxLength       = $VersionSchema.properties.PackageIdentifier.maxLength
            PackageVersion            = $InstallerSchema.definitions.PackageVersion.pattern
            VersionMaxLength          = $VersionSchema.properties.PackageVersion.maxLength
            InstallerSha256           = $InstallerSchema.definitions.Installer.properties.InstallerSha256.pattern
            InstallerUrl              = $InstallerSchema.definitions.Installer.properties.InstallerUrl.pattern
            InstallerUrlMaxLength     = $InstallerSchema.definitions.Installer.properties.InstallerUrl.maxLength
            ValidArchitectures        = $InstallerSchema.definitions.Installer.properties.Architecture.enum
            ValidInstallerTypes       = $InstallerSchema.definitions.InstallerType.enum
            SilentSwitchMaxLength     = $InstallerSchema.definitions.InstallerSwitches.properties.Silent.maxLength
            ProgressSwitchMaxLength   = $InstallerSchema.definitions.InstallerSwitches.properties.SilentWithProgress.maxLength
            CustomSwitchMaxLength     = $InstallerSchema.definitions.InstallerSwitches.properties.Custom.maxLength
            SignatureSha256           = $InstallerSchema.definitions.Installer.properties.SignatureSha256.pattern
            FamilyName                = $InstallerSchema.definitions.PackageFamilyName.pattern
            FamilyNameMaxLength       = $InstallerSchema.definitions.PackageFamilyName.maxLength
            PackageLocale             = $LocaleSchema.properties.PackageLocale.pattern
            InstallerLocaleMaxLength  = $InstallerSchema.definitions.Locale.maxLength
            ProductCodeMinLength      = $InstallerSchema.definitions.ProductCode.minLength
            ProductCodeMaxLength      = $InstallerSchema.definitions.ProductCode.maxLength
            MaxItemsFileExtensions    = $InstallerSchema.definitions.FileExtensions.maxItems
            MaxItemsProtocols         = $InstallerSchema.definitions.Protocols.maxItems
            MaxItemsCommands          = $InstallerSchema.definitions.Commands.maxItems
            MaxItemsSuccessCodes      = $InstallerSchema.definitions.InstallerSuccessCodes.maxItems
            MaxItemsInstallModes      = $InstallerSchema.definitions.InstallModes.maxItems
            PackageLocaleMaxLength    = $LocaleSchema.properties.PackageLocale.maxLength
            PublisherMaxLength        = $LocaleSchema.properties.Publisher.maxLength
            PackageNameMaxLength      = $LocaleSchema.properties.PackageName.maxLength
            MonikerMaxLength          = $LocaleSchema.definitions.Tag.maxLength
            GenericUrl                = $LocaleSchema.definitions.Url.pattern
            GenericUrlMaxLength       = $LocaleSchema.definitions.Url.maxLength
            AuthorMinLength           = $LocaleSchema.properties.Author.minLength
            AuthorMaxLength           = $LocaleSchema.properties.Author.maxLength
            LicenseMaxLength          = $LocaleSchema.properties.License.maxLength
            CopyrightMinLength        = $LocaleSchema.properties.Copyright.minLength
            CopyrightMaxLength        = $LocaleSchema.properties.Copyright.maxLength
            TagsMaxItems              = $LocaleSchema.properties.Tags.maxItems
            ShortDescriptionMaxLength = $LocaleSchema.properties.ShortDescription.maxLength
            DescriptionMinLength      = $LocaleSchema.properties.Description.minLength
            DescriptionMaxLength      = $LocaleSchema.properties.Description.maxLength
            ValidInstallModes         = $InstallerSchema.definitions.InstallModes.items.enum
            FileExtension             = $InstallerSchema.definitions.FileExtensions.items.pattern
            FileExtensionMaxLength    = $InstallerSchema.definitions.FileExtensions.items.maxLength
            ReleaseNotesMinLength     = $LocaleSchema.properties.ReleaseNotes.MinLength
            ReleaseNotesMaxLength     = $LocaleSchema.properties.ReleaseNotes.MaxLength
        }
    ) -Option Constant

    ########## INITIALIZATION ###########
    #
    # This section is the beginning of the code, where the values are finaly initialized and
    # the update process can begin. This is to be considered the point where the user enters
    # the script. The flow of the script below this point should be kept as easy to read as
    # possible, and descriptive functions and variables should be used.
    #
    #####################################
    New-Variable -Name 'ScriptSettings' -Value $(Initialize-ScriptSettings) -Option AllScope -Force
    if ($null -eq $ScriptLogging) { New-Variable -Name 'ScriptLogging' -Value $(Initialize-ScriptLogging) -Option AllScope }
    $MyInvocation | Select-Object -Property MyCommand, BoundParameters, PSScriptRoot | Out-Log
    if ($IsDotSourced) { exit }
}

# This section is run after begin, and can be run multiple times if multiple values are passed in through the pipeline
# This section should only execute when the script contains an input object, since this is where the actual updating of manifests is performed
Process {
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        $InputObject | Out-Log
        $_ValidationResult = Validate-InputObject $InputObject
        if ($_ValidationResult.StatusCode -eq $SuccessStatusCode) {
            switch ($InputObject.Action) {
                # The manifests have been created and we can now finalize the information
                'Finalize' {
                    $_VersionFolder = (Get-VersionStructure $InputObject.PackageIdentifier $InputObject.PackageVersion).VersionFolder
                    if ($InputObject.DoValidation -and $WingetIsInstalled) {
                        winget validate $_VersionFolder
                        $_ManifestValidationResult = $(if ($?) { [ReturnValue]::Success() } else { [ReturnValue]::new(400, 'Validation Failed', 'The manifest could not be validated', 2) })
                    }
                    if ($InputObject.DoSandboxTest -and $SandboxIsEnabled) {
                        $_DidSandboxTest = $true
                        if (Test-Path -Path "$PSScriptRoot\SandboxTest.ps1") {
                            $SandboxScriptPath = (Resolve-Path "$PSScriptRoot\SandboxTest.ps1").Path
                        } else {
                            while ([string]::IsNullOrWhiteSpace($SandboxScriptPath)) {
                                Write-Host
                                Write-Host -ForegroundColor 'Green' -Object 'SandboxTest.ps1 not found, input path'
                                $SandboxScriptPath = Read-Host -Prompt 'SandboxTest.ps1' | TrimString
                            }
                        }
                        if ($InputObject.DoValidation) {
                            & $SandboxScriptPath -Manifest $_VersionFolder -SkipManifestValidation
                        } else {
                            & $SandboxScriptPath -Manifest $_VersionFolder
                        }
                    } else {
                        $_DidSandboxTest = $false
                    }
                    if ('ask' -eq $InputObject.PullRequest.AutoSubmit) {
                        $_PRContent = Request-PRSubmission @{
                            Validated = $(if ($_ManifestValidationResult.StatusCode -eq $SuccessStatusCode -or $InputObject.PullRequest.CommitType -eq 'Remove') { $true } else { $false })
                            Tested    = $(if ($_DidSandboxTest -or $InputObject.PullRequest.CommitType -eq 'Remove') { $true } else { $false })
                        }
                        $_DoPRSubmission = $_PRContent.AutoSubmit
                    } else { $_DoPRSubmission = $InputObject.PullRequest.AutoSubmit }
                    if ($_DoPRSubmission) {
                        $_PRBody = $(if ($_PRContent -and -Not $InputObject.PullRequest.PRBody) { $_PRContent.PRBody } else { $InputObject.PullRequest.PRBody })
                        if ($InputObject.PullRequest.BodyPrependText) { $_PRBody = @($InputObject.PullRequest.BodyPrependText) + @($_PRBody) }
                        $_CurrentBranch = git branch --show-current
                        $_BranchCreated = Write-NewBranch -PackageIdentifier $InputObject.PackageIdentifier -CommitMessage "$($InputObject.PullRequest.CommitType) - $($InputObject.PackageIdentifier) $($InputObject.PackageVersion)"
                        if ($_BranchCreated) {
                            $_PRBodyFile = (New-TemporaryFile).FullName
                            Set-Content -Path $_PRBodyFile -Value $_PRBody | Out-Null
                            gh pr create --body-file $_PRBodyFile -f
                            Remove-Item -Path $_PRBodyFile -Force
                        }
                        git switch $_CurrentBranch
                    }
                }
                # User Selected to remove a manifest
                'Delete' {
                    Remove-ManifestVersion (Get-VersionStructure $InputObject.PackageIdentifier $InputObject.PackageVersion).VersionFolder
                    $_OutputObject = @{
                        PackageIdentifier = $InputObject.PackageIdentifier
                        PackageVersion    = $InputObject.PackageVersion
                        Action            = 'Finalize'
                        DoValidation      = $false
                        DoSandboxTest     = $false
                        PullRequest       = @{
                            AutoSubmit      = $InputObject.PullRequest.AutoSubmit
                            PRBody          = $(if ($InputObject.PullRequest.Keys -contains 'PRBody') { $InputObject.PullRequest.PRBody } else { $null })
                            BodyPrependText = $(if ($InputObject.PullRequest.Keys -contains 'BodyPrependText') { $InputObject.PullRequest.BodyPrependText } else { $null })
                            CommitType      = 'Remove'
                        }
                    }
                    # Call the script one more time to finalize the things which need to be done after manifest deletion
                    if ($_OutputObject) {
                        $_PassedObject = @{'InputObject' = $_OutputObject }
                        & $PSCommandPath @_PassedObject
                    }
                }
                # User is performing an automatic upgrade
                'Auto' {
                    $_VersionStructure = Get-VersionStructure $InputObject.PackageIdentifier $InputObject.PackageVersion
                    if ($null -eq $_VersionStructure) {
                        $_PackageStructure = Get-PackageStructure $InputObject.PackageIdentifier
                        if ($_PackageStructure -and $_PackageStructure.PackageVersions.Length -gt 0) {
                            $_VersionStructure = Get-VersionStructure $InputObject.PackageIdentifier $_PackageStructure.PackageVersions[$_PackageStructure.PackageVersions.Length - 1]
                        } else {
                            $_VersionStructure.ManifestType = 'None'
                        }
                    }
                    Write-Host -ForegroundColor 'Yellow' "Found Package Version $(Split-Path $_VersionStructure.VersionFolder -Leaf)"
                    switch ($_VersionStructure.ManifestType) {
                        'MultiManifest' { $_Manifests = Import-MultiManifest $_VersionStructure }
                        'Singleton' { $_Manifests = Import-SingletonManifest $_VersionStructure }
                        default {
                            "The manifest type of $($InputObject.PackageIdentifier) $($InputObject.PackageVersion) could not be determined" | Out-Log
                            Write-Host -ForegroundColor 'Red' "Error when processing $($InputObject.PackageIdentifier) $($InputObject.PackageVersion)"
                            return
                        }
                    }
                    # The manifests should now be loaded and are ready for processing
                    $_KnownInstallers = @{}
                    foreach ($_Installer in $_Manifests.Installer.Installers) {
                        if ($_Installer.InstallerUrl -notin $_KnownInstallers.Keys) {
                            Write-Host "Processing $($_Installer.InstallerUrl)"
                            $_InstallerUrlResponse = Get-UrlResponse $_Installer.InstallerUrl
                            $_InstallerFile = Get-InstallerFile $_InstallerUrlResponse "$($InputObject.PackageIdentifier) v$($InputObject.PackageVersion)"
                            $_InstallerObject = @{
                                InstallerSha256 = (Get-FileHash -Path $_InstallerFile.FullName -Algorithm SHA256).Hash
                            }
                            if ([System.IO.Path]::GetExtension($_InstallerFile.FullName -match 'msi$') -or $_Installer.InstallerType -match '(msi|wix)$') {
                                # TODO Fetch Product Code
                                # TODO Check if wix
                            }
                            if ([System.IO.Path]::GetExtension($_InstallerFile.FullName -match '(msix|appx)(bundle){0,1}$')) {
                                # TODO Fetch SignatureSha256
                                # TODO Fetch PackageFamilyName
                            }
                            $_KnownInstallers[$_Installer.InstallerUrl] = $_InstallerObject
                            Remove-Item $_InstallerFile
                        }
                        # Update using information from the known installers array
                        $_Installer['InstallerSha256'] = $_KnownInstallers[$_Installer.InstallerUrl].InstallerSha256
                        if ($_KnownInstallers[$_Installer.InstallerUrl].ProductCode) {
                            $_Installer['ProductCode'] = $_KnownInstallers[$_Installer.InstallerUrl].ProductCode
                        } elseif (($_Installer.Keys -contains 'ProductCode') -and ($_Installer.InstallerType -notmatch 'appx|msi|wix|burn')) {
                            $_Installer.Remove('ProductCode')
                        }
                        if ($_KnownInstallers[$_Installer.InstallerUrl].SignatureSha256) {
                            $_Installer['SignatureSha256'] = $_KnownInstallers[$_Installer.InstallerUrl].SignatureSha256
                        } elseif ($_Installer.Keys -contains 'SignatureSha256') {
                            $_Installer.Remove('SignatureSha256')
                        }
                        if ($_KnownInstallers[$_Installer.InstallerUrl].PackageFamilyName) {
                            $_Installer['PackageFamilyName'] = $_KnownInstallers[$_Installer.InstallerUrl].PackageFamilyName
                        } elseif ($_Installer.Keys -contains 'PackageFamilyName') {
                            $_Installer.Remove('PackageFamilyName')
                        }
                        if ($_Installer.Keys -contains 'ReleaseDate') { $_Installer.Remove('ReleaseDate') }
                        if ($_Installer.Keys -contains 'AppsAndFeaturesEntries') { $_Installer.Remove('AppsAndFeaturesEntries') }
                    }
                    $_Manifests.Installer.PackageVersion = $InputObject.PackageVersion
                    if ($_Manifests.defaultLocale.Keys -contains 'ReleaseNotes') { $_Manifests.defaultLocale.Remove('ReleaseNotes') }
                    if ($_Manifests.defaultLocale.Keys -contains 'ReleaseNotesUrl') { $_Manifests.defaultLocale.Remove('ReleaseNotesUrl') }
                    $_Manifests.defaultLocale.PackageVersion = $InputObject.PackageVersion
                    foreach ($_LocaleManifest in $_Manifests.Locales) {
                        $_LocaleManifest.PackageVersion = $InputObject.PackageVersion
                        if ($_LocaleManifest.Keys -contains 'ReleaseNotes') { $_LocaleManifest.Remove('ReleaseNotes') }
                        if ($_LocaleManifest.Keys -contains 'ReleaseNotesUrl') { $_LocaleManifest.Remove('ReleaseNotesUrl') }
                    }
                    # TODO Write Manifest Files
                    return $_Manifests
                }
            }
            return
        } else {
            Write-Host -ForegroundColor 'Red' "Error when processing $($InputObject.PackageIdentifier) $($InputObject.PackageVersion)"
            Write-Host -ForegroundColor 'Red' $_ValidationResult.ErrorString()
        }
    }
}

# This section is run after processing completes. It is only run once
# This section should only execute when the script does not contain an input object, since this is where the recursion of the script will occur
End {
    if (!$PSBoundParameters.ContainsKey('InputObject')) {
        ########## USER INTERACTION ###########
        #
        # This section is the beginning of user interaction. If the script was not called with
        # an input object, it should go through the standard user flow
        #
        #######################################
        If (!$PSBoundParameters.ContainsKey('Mode')) {
            Write-MulticolorOutput $ModeChoiceMenu
            Write-Host -NoNewline 'Selection: '
            $_KeyCode = Read-KeyPress
        } Else {
            $_KeyCode = 'D' + $Mode
        }

        switch ($_KeyCode) {
            'D1' { New-Variable -Name 'UserSelectedMode' -Value 'New' }
            'D2' { New-Variable -Name 'UserSelectedMode' -Value 'Quick' }
            'D3' { New-Variable -Name 'UserSelectedMode' -Value 'Metadata' }
            'D4' { New-Variable -Name 'UserSelectedMode' -Value 'Locale' }
            'D5' { New-Variable -Name 'UserSelectedMode' -Value 'Remove' }
            Default { New-Variable -Name 'UserSelectedMode' -Value 'Quit' }
        }

        switch ($UserSelectedMode) {
            'Quit' {
                Write-Host
                exit 1
            }
            'Remove' {
                $OutputObject = @{
                    PackageIdentifier = ''
                    PackageVersion    = ''
                    Action            = 'Delete'
                    DoValidation      = $false
                    DoSandboxTest     = $false
                    PullRequest       = @{
                        AutoSubmit = 'ask'
                    }
                }
                # TODO Confirm user wishes to delete a manifest
                if ($PSBoundParameters.ContainsKey('PackageIdentifier')) { $OutputObject['PackageIdentifier'] = $PackageIdentifier }
                if ($PSBoundParameters.ContainsKey('PackageVersion')) { $OutputObject['PackageVersion'] = $PackageVersion }
                $_ValidationResult = Validate-PackageVersionExists $OutputObject.PackageIdentifier $OutputObject.PackageVersion
                while ($_ValidationResult.StatusCode -ne $SuccessStatusCode) {
                    Write-Host -ForegroundColor 'Red' $_ValidationResult.ErrorString()
                    $OutputObject['PackageIdentifier'] = Request-PackageIdentifier
                    $OutputObject['PackageVersion'] = Request-PackageVersion
                    $_ValidationResult = Validate-PackageVersionExists $OutputObject.PackageIdentifier $OutputObject.PackageVersion
                }
                # TODO Prompt for removal reason
            }
            'New' {
                # Go through creation of new package
                $OutputObject = @{
                    PackageIdentifier = ''
                    PackageVersion    = ''
                    Action            = 'Create'
                    DoValidation      = $false
                    DoSandboxTest     = $false
                    PullRequest       = @{
                        AutoSubmit = 'ask'
                    }
                }
                if ($PSBoundParameters.ContainsKey('PackageIdentifier')) { $OutputObject['PackageIdentifier'] = $PackageIdentifier }
                if ($PSBoundParameters.ContainsKey('PackageVersion')) { $OutputObject['PackageVersion'] = $PackageVersion }
                # Request Package Identifier and Version if they haven't been provided already
                if (!$OutputObject.PackageIdentifier) { $OutputObject['PackageIdentifier'] = Request-PackageIdentifier }
                if (!$OutputObject.PackageVersion) { $OutputObject['PackageVersion'] = Request-PackageVersion }
                # Check if the package exists to determine how the recursion gets handled
                $_ValidationResult = Validate-PackageVersionExists $OutputObject.PackageIdentifier $OutputObject.PackageVersion
                if ($_ValidationResult.StatusCode -eq $SuccessStatusCode) {
                    # Recursion creates new manifests by default; If the package exists, switch to modification mode
                    $OutputObject['Action'] = 'Modify'
                }
            }
            'Quick' {
                # Go through update of package URLs / ReleaseDate then auto update
            }
            'Metadata' {
                # Go through update of Metadata only
            }
            'Locale' {
                # Create or update a locale
            }
            'Auto' {
                # Auto update
            }

        }
        if ($OutputObject) {
            $PassedObject = @{'InputObject' = $OutputObject }
            & $PSCommandPath @PassedObject
        }
    }
    if ($ScriptLogging.LogFile) {
        $_LogContents = Get-Content $ScriptLogging.LogFile
        $_LogContents | ForEach-Object { $_.Trim() } | Set-Content $ScriptLogging.LogFile
    }
}
