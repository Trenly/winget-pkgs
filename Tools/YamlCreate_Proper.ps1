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
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope = 'Function', Target = 'Get-OffsetBytes',
  Justification = 'Ths function both consumes and outputs an array of bytes. The pluralized name is required to adequately describe the functions purpose')]

param
(
  [Parameter(Mandatory = $false)]
  [string] $PackageIdentifier,
  [Parameter(Mandatory = $false)]
  [string] $PackageVersion,
  [Parameter(Mandatory = $false)]
  [int] $Mode,
  [switch] $Settings,
  [switch] $AutoUpgrade,
  [switch] $Help,
  [switch] $SkipPRCheck,
  [switch] $Preserve
)

enum ScriptModes {
  FullUpdate
  QuickUpdateVersion
  MetadataUpdate
  NewLocale
  RemoveManifest
  MoveManifests
  AutomaticUpdate = [int]::MaxValue
}

enum AlwaysNeverOption {
  Ask
  Never
  Always
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
  $InformationPreference = $script:OriginalInformationPreference
  $ErrorActionPreference = $script:OriginalErrorActionPreference
  $PSDefaultParameterValues = $script:OriginalDefaultParameters
  $ofs = $script:OriginalOfs
  $env:TEMP = $script:OriginalTempDirectory

  # Dispose of resources
  $script:HttpClient.Dispose()

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
# Description: If Virtual Terminal is supported, convert the operation code to its virtual terminal sequence
# Inputs: Integer. Operation Code
# Outputs: Nullable Virtual Terminal Sequence String
####
filter Initialize-VirtualTerminalSequence {
  if ($script:vtSupported) {
    "$([char]0x001B)[${_}m"
    return "$([char]0x001B)[${_}m"
  }
}

####
# Description: Gets the setting enum option associated with multi-state settings
# Inputs: Setting Text
# Outputs: Setting mode from enum
####
filter Initialize-AlwaysNeverSetting {
  # Case insensitively convert strings to enum
  if ($_ -eq 'always') { return [AlwaysNeverOption]::Always }
  if ($_ -eq 'never') { return [AlwaysNeverOption]::Always }
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
  }
  catch {
    Write-Error 'This script must be run from inside a clone of the winget-pkgs repository' -ErrorAction Stop
  }

  # Get the URL for the `upstream` remote
  ($script:OriginalRemoteUpstreamUri = $(git remote get-url upstream)) *> $null
  # If the `upstream` remote exists, set it to the upstream remote that is needed for the script
  if ($script:OriginalRemoteUpstreamUri) {
    Write-Verbose "Upstream already exists with URI (${script:OriginalRemoteUpstreamUri}). Temporarily setting ${script:WinGetUpstreamUri} as remote upstream"
    git remote set-url upstream $script:WinGetUpstreamUri
  }
  else {
    # Otherwise, permanently set the remote
    Write-Information "${script:vtForegroundYellow}Upstream does not exist. Permanently adding ${script:vtForegroundBlue}${script:vtUnderline}${script:WinGetUpstreamUri}${script:vtNotUnderline}${script:vtForegroundYellow} as remote upstream${script:vtDefault}"
    git remote add upstream $script:WinGetUpstreamUri
  }
}

####
# Description: Gets the content of a file from a URI
# Inputs: Remote URI
# Outputs: File Contents or FileInfo
####
function Get-RemoteContent {
  param (
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [String] $URL,
    [String] $OutputPath = '',
    [switch] $Raw
  )
  Write-Debug "Attempting to fetch content from $URL"
  # Check if the URL is valid before trying to download
  $response = [String]::IsNullOrWhiteSpace($URL) ? @{StatusCode = 400 } : $(Invoke-WebRequest -Uri $URL -Method Head -ErrorAction SilentlyContinue) # If the URL is null, return a status code of 400
  if ($response.StatusCode -ne 200) {
    Write-Debug "Fetching remote content from $URL returned status code $($response.StatusCode)"
    return $null
  }
  $localFile = $OutputPath ? [System.IO.FileInfo]::new($OutputPath) : $(New-TemporaryFile) # If a path was specified, store it at that path; Otherwise use the temp folder
  Write-Debug "Remote content will be stored at $($localFile.FullName)"
  $script:CleanupPaths += $Raw ? @($localFile.FullName) : @() # Mark the file for cleanup when the script ends if the raw data was requested
  try {
    $downloadTask = $script:HttpClient.GetByteArrayAsync($URL)
    [System.IO.File]::WriteAllBytes($localfile.FullName, $downloadTask.Result)
  }
  catch {
    # If the download fails, write a zero-byte file anyways
    $null | Out-File $localFile.FullName
  }
  return $Raw ? $(Get-Content -Path $localFile.FullName) : $localFile # If the raw content was requested, return the content, otherwise, return the FileInfo object
}

####
# Description: Waits for the user to press a key
# Inputs: None
# Outputs: Key which was pressed
####
function Get-Keypress {
  do {
    $keyInfo = [Console]::ReadKey($false)
  } until ($keyInfo.Key)
  return $keyInfo.Key
}

####
# Description: Ensures a PowerShell module is installed
# Inputs: PowerShell Module Name
# Outputs: None
####
function Initialize-Module {
  param (
    [Parameter(Mandatory = $true)]
    [String] $Name
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
    }
    catch {
      Write-Error 'Could not install the NuGet package provider which is required to install script dependencies.' -ErrorAction Continue
      Write-Error "You may be able to resolve this by running: Install-PackageProvider -Name NuGet -MinimumVersion $($script:NuGetMinimumVersion.ToString())"
    }
  }

  Write-Verbose "Ensuring PowerShell module '$Name' is installed"
  if ($installedModules) {
    # If the module is installed, attempt to upgrade it
    Write-Debug "Found $Name in installed modules"
  }
  else {
    # If the module is not installed, attempt to install it
    try {
      Install-Module -Name $Name -Force -Repository PSGallery -Scope CurrentUser
    }
    catch {
      Write-Error "$Name was unable to be installed successfully"
    }
  }
  # Verify the module is installed and present
  try {
    if (!(Get-Module -Name $Name)) {
      Import-Module $Name
    }
  }
  catch {
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

####
# Description: Gets the specified bytes from a byte array
# Inputs: Array of Bytes, Integer offset, Integer Length
# Outputs: Array of bytes
####
function Get-OffsetBytes {
  param (
    [Parameter(Mandatory = $true)]
    [byte[]] $ByteArray,
    [Parameter(Mandatory = $true)]
    [int] $Offset,
    [Parameter(Mandatory = $true)]
    [int] $Length,
    [Parameter(Mandatory = $false)]
    [bool] $LittleEndian = $false # Bool instead of a switch for use with other functions
  )

  if ($Offset -gt $ByteArray.Length) { return @() } # Prevent null exceptions
  $Start = if ($LittleEndian) { $Offset + $Length - 1 } else { $Offset }
  $End = if ($LittleEndian) { $Offset } else { $Offset + $Length - 1 }
  return $ByteArray[$Start..$End]
}


####
# Description: Gets the PE Section Table of a file
# Inputs: Path to File
# Outputs: Array of Object if valid PE file, null otherwise
####
function Get-PESectionTable {
  # TODO: Switch to using FileReader to be able to seek through the file instead of reading from the start
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )
  # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  # The first 64 bytes of the file contain the DOS header. The first two bytes are the "MZ" signature, and the 60th byte contains the offset to the PE header.
  $DOSHeader = Get-Content -Path $Path -AsByteStream -TotalCount 64 -WarningAction 'SilentlyContinue'
  $MZSignature = Get-OffsetBytes -ByteArray $DOSHeader -Offset 0 -Length 2
  if ([Convert]::ToHexString($MZSignature) -cne '4D5A') { return $null } # The MZ signature is invalid
  $PESignatureOffsetBytes = Get-OffsetBytes -ByteArray $DOSHeader -Offset 60 -Length 4
  $PESignatureOffset = [BitConverter]::ToInt32($PESignatureOffsetBytes, 0)

  # These are known sizes
  $PESignatureSize = 4 # Bytes
  $COFFHeaderSize = 20 # Bytes
  $SectionTableEntrySize = 40 # Bytes

  # Read 24 bytes past the PE header offset to get the PE Signature and COFF header
  $RawBytes = Get-Content -Path $Path -AsByteStream -TotalCount $($PESignatureOffset + $PESignatureSize + $COFFHeaderSize) -WarningAction 'SilentlyContinue'
  $PESignature = Get-OffsetBytes -ByteArray $RawBytes -Offset $PESignatureOffset -Length $PESignatureSize
  if ([Convert]::ToHexString($PESignature) -cne '50450000') { return $null } # The PE header is invalid if it is not 'PE\0\0'

  # Parse out information from the header
  $COFFHeaderBytes = Get-OffsetBytes -ByteArray $RawBytes -Offset $($PESignatureOffset + $PESignatureSize) -Length $COFFHeaderSize
  $MachineTypeBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 0 -Length 2
  $NumberOfSectionsBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 2 -Length 2
  $TimeDateStampBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 4 -Length 4
  $PointerToSymbolTableBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 8 -Length 4
  $NumberOfSymbolsBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 12 -Length 4
  $SizeOfOptionalHeaderBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 16 -Length 2
  $HeaderCharacteristicsBytes = Get-OffsetBytes -ByteArray $COFFHeaderBytes -Offset 18 -Length 2

  # Convert the data into real numbers
  $NumberOfSections = [BitConverter]::ToInt16($NumberOfSectionsBytes, 0)
  $TimeDateStamp = [BitConverter]::ToInt32($TimeDateStampBytes, 0)
  $SymbolTableOffset = [BitConverter]::ToInt32($PointerToSymbolTableBytes, 0)
  $NumberOfSymbols = [BitConverter]::ToInt32($NumberOfSymbolsBytes, 0)
  $OptionalHeaderSize = [BitConverter]::ToInt16($SizeOfOptionalHeaderBytes, 0)

  # Read the section table from the file
  $SectionTableStart = $PESignatureOffset + $PESignatureSize + $COFFHeaderSize + $OptionalHeaderSize
  $SectionTableLength = $NumberOfSections * $SectionTableEntrySize
  $RawBytes = Get-Content -Path $Path -AsByteStream -TotalCount $($SectionTableStart + $SectionTableLength) -WarningAction 'SilentlyContinue'
  $SectionTableContents = Get-OffsetBytes -ByteArray $RawBytes -Offset $SectionTableStart -Length $SectionTableLength

  $SectionData = @();
  # Parse each of the sections
  foreach ($Section in 0..$($NumberOfSections - 1)) {
    $SectionTableEntry = Get-OffsetBytes -ByteArray $SectionTableContents -Offset ($Section * $SectionTableEntrySize) -Length $SectionTableEntrySize

    # Get the raw bytes
    $SectionNameBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 0 -Length 8
    $VirtualSizeBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 8 -Length 4
    $VirtualAddressBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 12 -Length 4
    $SizeOfRawDataBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 16 -Length 4
    $PointerToRawDataBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 20 -Length 4
    $PointerToRelocationsBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 24 -Length 4
    $PointerToLineNumbersBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 28 -Length 4
    $NumberOfRelocationsBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 32 -Length 2
    $NumberOfLineNumbersBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 34 -Length 2
    $SectionCharacteristicsBytes = Get-OffsetBytes -ByteArray $SectionTableEntry -Offset 36 -Length 4

    # Convert the data into real values
    $SectionName = [Text.Encoding]::UTF8.GetString($SectionNameBytes)
    $VirtualSize = [BitConverter]::ToInt32($VirtualSizeBytes, 0)
    $VirtualAddressOffset = [BitConverter]::ToInt32($VirtualAddressBytes, 0)
    $SizeOfRawData = [BitConverter]::ToInt32($SizeOfRawDataBytes, 0)
    $RawDataOffset = [BitConverter]::ToInt32($PointerToRawDataBytes, 0)
    $RelocationsOffset = [BitConverter]::ToInt32($PointerToRelocationsBytes, 0)
    $LineNumbersOffset = [BitConverter]::ToInt32($PointerToLineNumbersBytes, 0)
    $NumberOfRelocations = [BitConverter]::ToInt16($NumberOfRelocationsBytes, 0)
    $NumberOfLineNumbers = [BitConverter]::ToInt16($NumberOfLineNumbersBytes, 0)

    # Build the object
    $SectionEntry = [PSCustomObject]@{
      SectionName                 = $SectionName
      SecitonNameBytes            = $SectionNameBytes
      VirtualSize                 = $VirtualSize
      VirtualAddressOffset        = $VirtualAddressOffset
      SizeOfRawData               = $SizeOfRawData
      RawDataOffset               = $RawDataOffset
      RelocationsOffset           = $RelocationsOffset
      LineNumbersOffset           = $LineNumbersOffset
      NumberOfRelocations         = $NumberOfRelocations
      NumberOfLineNumbers         = $NumberOfLineNumbers
      SectionCharacteristicsBytes = $SectionCharacteristicsBytes
    }
    # Add the section to the output
    $SectionData += $SectionEntry
  }

  return $SectionData
}

####
# Description: Checks if a file is a Zip archive
# Inputs: Path to File
# Outputs: Boolean. True if file is a zip file, false otherwise
# Note: This function does not differentiate between other Zipped installer types. Any specific types like MSIX still result in an Zip file.
#       Use this function with care, as it may return overly broad results.
####
function Test-IsZip {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  # The first 4 bytes of zip files are the same. This reference string is just the Base64 encoding of the bytes
  $referenceBytes = 'UEsDBA=='
  return [Convert]::ToBase64String($(Get-Content -Path $Path -AsByteStream -TotalCount 4 -WarningAction 'SilentlyContinue')) -ceq $referenceBytes
}

####
# Description: Checks if a file is a Zip archive
# Inputs: Path to File
# Outputs: Boolean. True if file is a zip file, false otherwise
# Note: This function does not differentiate between other Zipped installer types. Any specific types like MSIX still result in an Zip file.
#       Use this function with care, as it may return overly broad results.
####
function Test-IsMsix {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )
  if (!(Test-IsZip -Path $Path)) { return $false } # MSIX are really just a special type of Zip file
  Write-Debug 'Extracting file contents as a zip archive'
  $FileObject = Get-Item -Path $Path
  $temporaryFilePath = Join-Path -Path $env:TEMP -ChildPath "$($FileObject.BaseName).zip" # Expand-Archive only works if the file is a zip file
  $expandedArchivePath = Join-Path -Path $env:TEMP -ChildPath $(New-Guid)
  Copy-Item -Path $Path -Destination $temporaryFilePath
  Expand-Archive -Path $temporaryFilePath -DestinationPath $expandedArchivePath
  Write-Debug 'Marking extracted files for cleanup'
  $script:CleanupPaths += @($temporaryFilePath; $expandedArchivePath)

  # There are a few different indicators that a package can be installed with MSIX technology, look for any of these file names
  $msixIndicators = @('AppxSignature.p7x'; 'AppxManifest.xml'; 'AppxBundleManifest.xml')
  foreach ($filename in $msixIndicators) {
    if (Get-ChildItem -Path $expandedArchivePath -Recurse -Depth 3 -Filter $filename) { return $true } # If any of the files is found, it is an msix
  }
  return $false
}

####
# Description: Checks if a file is an MSI installer
# Inputs: Path to File
# Outputs: Boolean. True if file is an MSI installer, false otherwise
# Note: This function does not differentiate between MSI installer types. Any specific packagers like WIX still result in an MSI installer.
#       Use this function with care, as it may return overly broad results.
####
function Test-IsMsi {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  $MsiTables = Get-MSITable -Path $Path -ErrorAction SilentlyContinue
  if ($MsiTables) { return $true }
  # If the table names can't be parsed, it is not an MSI
  return $false
}

####
# Description: Checks if a file is a WIX installer
# Inputs: Path to File
# Outputs: Boolean. True if file is a WIX installer, false otherwise
####
function Test-IsWix {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  $MsiTables = Get-MSITable -Path $Path -ErrorAction SilentlyContinue
  if (!$MsiTables) { return $false } # If the table names can't be parsed, it is not an MSI and cannot be WIX
  if ($MsiTables.Where({ $_.Table -match 'wix' })) { return $true } # If any of the table names match wix
  if (Get-MSIProperty -Path $Path -Property '*wix*' -ErrorAction SilentlyContinue) { return $true } # If any of the keys in the property table match wix
  # TODO: Also Check the Metadata of the file
}

####
# Description: Checks if a file is a Nullsoft installer
# Inputs: Path to File
# Outputs: Boolean. True if file is a Nullsoft installer, false otherwise
####
function Test-IsNullsoft {
  # TODO: Switch to using FileReader to be able to seek through the file instead of reading from the start
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )
  $SectionTable = Get-PESectionTable -Path $Path
  if (!$SectionTable) { return $false } # If the section table is null, it is not an EXE and therefore not nullsoft
  $LastSection = $SectionTable | Sort-Object -Property RawDataOffset -Descending | Select-Object -First 1
  $PEOverlayOffset = $LastSection.RawDataOffset + $LastSection.SizeOfRawData
  # Get the first 8 bytes of the PE Overlay
  $RawBytes = Get-Content -Path $Path -AsByteStream -TotalCount $($PEOverlayOffset + 8) -WarningAction 'SilentlyContinue'
  $PresumedHeaderBytes = Get-OffsetBytes -ByteArray $RawBytes -Offset $($PEOverlayOffset + 4) -Length 4 -LittleEndian $true
  $PresumedNullosftHeader = [Convert]::ToHexString($PresumedHeaderBytes)

  if ($PresumedNullosftHeader -ceq 'DEADBEEF') { return $true }
  if ($PresumedNullosftHeader -ceq 'DEADBEED') { return $true }
  return $false
}

####
# Description: Checks if a file is an Inno installer
# Inputs: Path to File
# Outputs: Boolean. True if file is an Inno installer, false otherwise
####
function Test-IsInno {
  # TODO: Switch to using FileReader to be able to seek through the file instead of reading from the start
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  $SectionTable = Get-PESectionTable -Path $Path
  if (!$SectionTable) { return $false } # If the section table is null, it is not an EXE and therefore not nullsoft
  $ResourceSectionDetails = $SectionTable | Where-Object { $_.SectionName -eq '.rsrc' }
  if (!$ResourceSectionDetails) { return $false } # If there is no resource section, the file cannot be inno

  # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  $RawBytes = Get-Content -Path $Path -AsByteStream -TotalCount $($ResourceSectionDetails.RawDataOffset + $ResourceSectionDetails.SizeOfRawData) -WarningAction 'SilentlyContinue'
  $ResourceSectionData = Get-OffsetBytes -ByteArray $RawBytes -Offset $ResourceSectionDetails.RawDataOffset -Length $ResourceSectionDetails.SizeOfRawData

  $ResourceDirectoryTableSize = 16
  $ResourceEntrySize = 8
  # The resource directory is at the start of the .rsrc section
  $ResourceDirectoryHeader = Get-OffsetBytes -ByteArray $ResourceSectionData -Offset 0 -Length $ResourceDirectoryTableSize

  # Parse out the header information
  $ResourceCharacteristicsBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 0 -Length 4
  $TimeDateStampBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 4 -Length 4
  $MajorVersionBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 8 -Length 2
  $MinorVersionBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 10 -Length 2
  $NumberOfNameEntriesBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 12 -Length 2
  $NumberOfIdEntriesBytes = Get-OffsetBytes -ByteArray $ResourceDirectoryHeader -Offset 14 -Length 2

  # Convert to real numbers
  $ResourceTimeDateStamp = [BitConverter]::ToInt32($TimeDateStampBytes, 0)
  $MajorVersion = [BitConverter]::ToInt16($MajorVersionBytes, 0)
  $MinorVersion = [BitConverter]::ToInt16($MinorVersionBytes, 0)
  $NumberOfNameEntries = [BitConverter]::ToInt16($NumberOfNameEntriesBytes, 0)
  $NumberOfIdEntries = [BitConverter]::ToInt16($NumberOfIdEntriesBytes, 0)

  # return [PSCustomObject]@{
  #   Characteristics = $ResourceCharacteristicsBytes
  #   TimeDateStamp = $ResourceTimeDateStamp
  #   MajorVersion = $MajorVersion
  #   MinorVersion = $MinorVersion
  #   NamedEntries = $NumberOfNameEntries
  #   IdEntries = $NumberOfIdEntries
  # }


  # Get all of the resources at the first level
  $RootEntryCount = $NumberOfNameEntries + $NumberOfIdEntries
  $resources = @()
  foreach ($Entry in 0..$($RootEntryCount - 1)) {
    $EntryOffset = $ResourceDirectoryTableSize + ($ResourceEntrySize * $Entry)
    $EntryData = Get-OffsetBytes -ByteArray $ResourceSectionData -Offset $EntryOffset -Length $ResourceEntrySize

    # Parse raw data
    $EntryIdentifierBytes = Get-OffsetBytes -ByteArray $EntryData -Offset 0 -Length 4
    $EntryDataOffsetBytes = Get-OffsetBytes -ByteArray $EntryData -Offset 4 -Length 4

    # Convert to real values
    $EntryIdentifierAsName = [Text.Encoding]::UTF8.GetString($EntryIdentifierBytes)
    $EntryIdentifierAsId = [BitConverter]::ToInt32($EntryIdentifierBytes, 0)
    $EntryDataOffset = [BitConverter]::ToInt32($EntryDataOffsetBytes, 0)

    $ResourceEntry = [PSCustomObject]@{
      Name = $EntryIdentifierAsName
      Id = $EntryIdentifierAsId
      DataOffset = $EntryDataOffset
      IdenfitiferBytes = $EntryIdentifierBytes
      DataOffsetBytes = $EntryDataOffsetBytes
    }
    $resources += $ResourceEntry
  }

  return $resources
  # The first 264 bytes of most Inno installers are the same. This reference string is just the Base64 encoding of the bytes
  $referenceBytes = 'TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAALoQAA4ftAnNIbgBTM0hkJBUaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZXIgV2luMzINCiQ3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBFAABMAQoA'
  return [Convert]::ToBase64String($(Get-Content -Path $Path -AsByteStream -TotalCount 264 -WarningAction 'SilentlyContinue')) -ceq $referenceBytes
  # TODO: Improve detection - doesn't seem fully accurate
}

####
# Description: Checks if a file is a Burn installer
# Inputs: Path to File
# Outputs: Boolean. True if file is an Burn installer, false otherwise
####
function Test-IsBurn {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  $SectionTable = Get-PESectionTable -Path $Path
  if (!$SectionTable) { return $false } # If the section table is null, it is not an EXE and therefore not Burn
  if ($SectionTable.SectionName -contains '.wixburn') { return $true }
  return $false
}

####
# Description: Attempts to identify the type of installer from a file path
# Inputs: Path to File
# Outputs: Null if unknown type. String if known type
####
Function Resolve-InstallerType {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $Path
  )

  # Ordering is important here due to the specificity achievable by each of the detection methods
  if (Test-IsWix -Path $Path) { return 'wix' }
  if (Test-IsMsi -Path $Path) { return 'msi' }
  if (Test-IsMsix -Path $Path) { return 'msix' }
  if (Test-IsZip -Path $Path) { return 'zip' }
  if (Test-IsNullsoft -Path $Path) { return 'nullsoft' }
  if (Test-IsInno -Path $Path) { return 'inno' }
  if (Test-IsBurn -Path $Path) { return 'burn' }
  return $null
}

# Versions
Write-Debug 'Setting required versions'
$script:ScriptVersion = '3.0.0-alpha'
$script:DefaultManifestVersion = '1.10.0'
$script:NuGetMinimumVersion = [System.Version]::Parse('2.8.5.201')

# Flags
Write-Debug 'Checking for supported features'
$script:vtSupported = (Get-Host).UI.SupportsVirtualTerminal
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
$script:OriginalInformationPreference = $InformationPreference
$script:OriginalErrorActionPreference = $ErrorActionPreference
$script:OriginalUICulture = [Threading.Thread]::CurrentThread.CurrentUICulture
$script:OriginalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
$script:OriginalDefaultParameters = $PSDefaultParameterValues
$script:OriginalOfs = $ofs
$script:OriginalTempDirectory = $env:TEMP
$script:OriginalRemoteUpstreamUri = $null # Initialized for later use

# Virtual Terminal
Write-Debug 'Initializing Virtual Terminal Sequences'
$script:vtDefault = 0 | Initialize-VirtualTerminalSequence
$script:vtBold = 1 | Initialize-VirtualTerminalSequence
$script:vtNotBold = 22 | Initialize-VirtualTerminalSequence
$script:vtUnderline = 4 | Initialize-VirtualTerminalSequence
$script:vtNotUnderline = 24 | Initialize-VirtualTerminalSequence
$script:vtNegative = 7 | Initialize-VirtualTerminalSequence
$script:vtPositive = 27 | Initialize-VirtualTerminalSequence
$script:vtForegroundBlack = 30 | Initialize-VirtualTerminalSequence
$script:vtForegroundRed = 31 | Initialize-VirtualTerminalSequence
$script:vtForegroundGreen = 32 | Initialize-VirtualTerminalSequence
$script:vtForegroundYellow = 33 | Initialize-VirtualTerminalSequence
$script:vtForegroundBlue = 34 | Initialize-VirtualTerminalSequence
$script:vtForegroundMagenta = 35 | Initialize-VirtualTerminalSequence
$script:vtForegroundCyan = 36 | Initialize-VirtualTerminalSequence
$script:vtForegroundWhite = 37 | Initialize-VirtualTerminalSequence
$script:vtForegroundDefault = 39 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBlack = 40 | Initialize-VirtualTerminalSequence
$script:vtBackgroundRed = 41 | Initialize-VirtualTerminalSequence
$script:vtBackgroundGreen = 42 | Initialize-VirtualTerminalSequence
$script:vtBackgroundYellow = 43 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBlue = 44 | Initialize-VirtualTerminalSequence
$script:vtBackgroundMagenta = 45 | Initialize-VirtualTerminalSequence
$script:vtBackgroundCyan = 46 | Initialize-VirtualTerminalSequence
$script:vtBackgroundWhite = 47 | Initialize-VirtualTerminalSequence
$script:vtBackgroundDefault = 49 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightBlack = 90 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightRed = 91 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightGreen = 92 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightYellow = 93 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightBlue = 94 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightMagenta = 95 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightCyan = 96 | Initialize-VirtualTerminalSequence
$script:vtForegroundBrightWhite = 97 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightBlack = 100 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightRed = 101 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightGreen = 102 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightYellow = 103 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightBlue = 104 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightMagenta = 105 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightCyan = 106 | Initialize-VirtualTerminalSequence
$script:vtBackgroundBrightWhite = 107 | Initialize-VirtualTerminalSequence

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
$script:HttpClient = New-Object System.Net.Http.HttpClient
$script:CleanupPaths = @()

# Terminal Setup
Write-Debug 'Setting required termininal properties'
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
$global:ProgressPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'Continue'
$ErrorActionPreference = 'Continue'
$PSDefaultParameterValues = @{ '*:Encoding' = 'UTF8'; 'ConvertTo-Json:Depth' = '10' }
$ofs = ', '
if (!$isWindows) { $env:TEMP = '/tmp/' }

#### Start of Early Exiting Main-Functions
if ($help) {
  Write-Information "${script:vtForegroundGreen}For full documentation of the script, see ${script:vtForegroundBlue}${script:vtUnderline}https://github.com/microsoft/winget-pkgs/tree/master/doc/tools/YamlCreate.md${script:vtNotUnderline}"
  Write-Information "${script:vtForegroundYellow}Usage: ${script:vtForegroundWhite}.\YamlCreate.ps1 [-PackageIdentifier <identifier>] [-PackageVersion <version>] [-Mode <1-5>] [-Settings] [-SkipPRCheck]"
  Write-Information "${script:vtDefault}"
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

#### Set up script dependencies
Initialize-Module -Name 'powershell-yaml'
Initialize-Module -Name 'MSI'
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
$script:ManifestVersion = if ($script:Settings.OverrideManifestVersion) { $script:Settings.OverrideManifestVersion } else { $script:DefaultManifestVersion }
$script:UseDirectSchemaLink = $env:GITHUB_ACTIONS -or (Invoke-WebRequest "https://aka.ms/winget-manifest.version.$script:ManifestVersion.schema.json" -UseBasicParsing).Content -match '<!doctype html>'

# Schemas
Write-Verbose "Determining URLs for Manifest Schemas (${script:ManifestVersion})"
Write-Debug "Use Direct Schema Link: $script:UseDirectSchemaLink"
$script:SchemaUrls = @{
  version       = if ($useDirectSchemaLink) { "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$script:ManifestVersion/manifest.version.$script:ManifestVersion.json" } else { "https://aka.ms/winget-manifest.version.$script:ManifestVersion.schema.json" }
  defaultLocale = if ($useDirectSchemaLink) { "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$script:ManifestVersion/manifest.defaultLocale.$script:ManifestVersion.json" } else { "https://aka.ms/winget-manifest.defaultLocale.$script:ManifestVersion.schema.json" }
  locale        = if ($useDirectSchemaLink) { "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$script:ManifestVersion/manifest.locale.$script:ManifestVersion.json" } else { "https://aka.ms/winget-manifest.locale.$script:ManifestVersion.schema.json" }
  installer     = if ($useDirectSchemaLink) { "https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$script:ManifestVersion/manifest.installer.$script:ManifestVersion.json" } else { "https://aka.ms/winget-manifest.installer.$script:ManifestVersion.schema.json" }
}
Write-Debug @"
Version: $($script:SchemaUrls.version)
DefaultLocale: $($script:SchemaUrls.defaultLocale)
Locale: $($script:SchemaUrls.locale)
Installer: $($script:SchemaUrls.installer)
"@

Write-Verbose 'Fetching Manifest Schemas'
$script:DefaultLocaleSchemaJSON = Get-RemoteContent $script:SchemaUrls.defaultLocale -Raw
$script:LocaleSchemaJSON = Get-RemoteContent $script:SchemaUrls.locale -Raw
$script:VersionSchemaJSON = Get-RemoteContent $script:SchemaUrls.version -Raw
$script:InstallerSchemaJSON = Get-RemoteContent $script:SchemaUrls.installer -Raw

Write-Verbose 'Parsing Schema Properties'
$script:DefaultLocaleSchema = $script:InstallerSchemaJSON | ConvertFrom-Json
$script:LocaleSchema = $script:InstallerSchemaJSON | ConvertFrom-Json
$script:VersionSchema = $script:InstallerSchemaJSON | ConvertFrom-Json
$script:InstallerSchema = $script:InstallerSchemaJSON | ConvertFrom-Json
$script:DefaultLocaleProperties = (ConvertTo-Yaml $script:DefaultLocaleSchema.properties | ConvertFrom-Yaml -Ordered).Keys
$script:LocaleProperties = (ConvertTo-Yaml $script:LocaleSchema.properties | ConvertFrom-Yaml -Ordered).Keys
$script:VersionProperties = (ConvertTo-Yaml $script:VersionSchema.properties | ConvertFrom-Yaml -Ordered).Keys
$script:InstallerProperties = (ConvertTo-Yaml $script:InstallerSchema.properties | ConvertFrom-Yaml -Ordered).Keys

# Extended Properties
Write-Debug 'Parsing Extended Schema Properties'
$script:InstallerSwitchProperties = (ConvertTo-Yaml $script:InstallerSchema.definitions.InstallerSwitches.properties | ConvertFrom-Yaml -Ordered).Keys
$script:InstallerEntryProperties = (ConvertTo-Yaml $script:InstallerSchema.definitions.Installer.properties | ConvertFrom-Yaml -Ordered).Keys
$script:InstallerDependencyProperties = (ConvertTo-Yaml $script:InstallerSchema.definitions.Dependencies.properties | ConvertFrom-Yaml -Ordered).Keys
$script:AppsAndFeaturesEntryProperties = (ConvertTo-Yaml $script:InstallerSchema.definitions.AppsAndFeaturesEntry.properties | ConvertFrom-Yaml -Ordered).Keys

# Variables used through the script
# These may or may not need to be initialized, but they are anyways just to be safe
$script:UserSelectedMode = $null
$script:ManifestsFolder = Get-ManifestsFolder
$script:ExecutionMode = $null

# Handle user selected mode
if ($PSBoundParameters.ContainsKey('Mode')) {

}

Invoke-CleanExit -1


