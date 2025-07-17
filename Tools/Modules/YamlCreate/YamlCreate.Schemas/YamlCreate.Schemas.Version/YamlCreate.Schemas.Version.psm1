####
# This file contains functions related to requesting and validating fields related to the version schema.
# Although there is a lot of overlap between each of the Test-* functions, they are kept separate to allow
# for clearer script flow and to avoid logic errors. While these functions could be combined with a single
# Test-Field function and appropriate parameters, it would make the code harder to read and maintain.
# Since these functions are not expected to change often, the current structure is preferred for clarity.
#
# Similarly, although the Request-* functions could likely be combined into a single function with parameters,
# they are kept separate for the same reasons as above. Each Request-* function is designed to handle a specific
# field and its validation rules, making it easier to understand and modify in the future.
####

# Make ValidationResult class available to this submodule
. $PSScriptRoot\..\..\ValidationResult.ps1

$VersionSchema = $null
$VersionSchemaProperties = $null

####
# Description: Handles the error case where the schema is not initialized
# Inputs: Void
# Outputs: Void
####
function Use-VersionSchema {
    if (!$script:VersionSchema -or !$script:VersionSchemaProperties) {
        Write-Error 'Version schema is not initialized. Please call Initialize-VersionSchema first.'
    }
}


####
# Description: Loads the locale schema into memory
# Inputs: Optional Override Schema Version
# Outputs: Void
####
function Initialize-VersionSchema {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )
    Write-Debug "Loading version schema for version $SchemaVersion"
    $script:VersionSchema = Get-SchemaJson -SchemaType 'version' -SchemaVersion $SchemaVersion | ConvertFrom-Json
    $script:VersionSchemaProperties = $script:VersionSchema.properties.PSObject.Properties.Name
}

####
# Description: Tests that a PackageIdentifier complies with the schema
# Inputs: PackageIdentifier
# Outputs: [ValidationResult]
####
function Test-PackageIdentifier {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [String] $Value
    )

    # Ensure the schema is loaded before proceeding
    Use-VersionSchema | Out-Null
    Write-Debug "Validating PackageIdentifier: $Value"

    $fieldMaxLength = $VersionSchema.properties.PackageIdentifier.maxLength
    $fieldPattern = $VersionSchema.properties.PackageIdentifier.pattern

    # Check for each validation rule on the field
    if ([String]::IsNullOrWhiteSpace($Value)) { return [ValidationResult]::new($false, 'Value cannot be empty') }
    if ($Value.Length -gt $fieldMaxLength) { return [ValidationResult]::new($false, "Value exceeds the maximum length of $fieldMaxLength characters") }
    if ($Value -notmatch $fieldPattern) { return [ValidationResult]::new($false, "Value does not match the required pattern: $fieldPattern") }

    # All the checks passed, the validation is successful
    return [ValidationResult]::new($true)
}


####
# Description: Requests a PackageIdentifier
# Inputs: None
# Outputs: Validated PackageIdentifier
####
function Request-PackageIdentifier {
    param ()

    Write-Information "${vtForegroundGreen}[Required] Enter the Package Identifier, in the following format <Publisher shortname.Application shortname>. For example: Microsoft.Excel${vtForegroundDefault}"

    while ($true) {
        $Value = Read-Host -Prompt 'Package Identifier'
        $validationResult = Test-PackageIdentifier -Value $Value

        if ($validationResult.IsValid) { break } # Exit the loop if validation is successful

        Write-Information "${vtForegroundRed}${validationResult}${vtForegroundDefault}"
    }

    return $Value
}

####
# Description: Tests that a PackageVersion complies with the schema
# Inputs: PackageVersion
# Outputs: [ValidationResult]
####
function Test-PackageVersion {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [String] $Value
    )

    # Ensure the schema is loaded before proceeding
    Use-VersionSchema | Out-Null
    Write-Debug "Validating PackageVersion: $Value"

    $fieldMaxLength = $VersionSchema.properties.PackageVersion.maxLength
    $fieldPattern = $VersionSchema.properties.PackageVersion.pattern

    # Check for each validation rule on the field
    if ([String]::IsNullOrWhiteSpace($Value)) { return [ValidationResult]::new($false, 'Value cannot be empty') }
    if ($Value.Length -gt $fieldMaxLength) { return [ValidationResult]::new($false, "Value exceeds the maximum length of $fieldMaxLength characters") }
    if ($Value -notmatch $fieldPattern) { return [ValidationResult]::new($false, "Value does not match the required pattern: $fieldPattern") }

    # All the checks passed, the validation is successful
    return [ValidationResult]::new($true)
}

####
# Description: Requests a PackageIdentifier
# Inputs: None
# Outputs: Validated PackageIdentifier
####
function Request-PackageVersion {
    param ()

    Write-Information "${vtForegroundGreen}[Required] Enter the version. for example: 1.33.7${vtForegroundDefault}"

    while ($true) {
        $Value = Read-Host -Prompt 'Version'
        $validationResult = Test-PackageVersion -Value $Value

        if ($validationResult.IsValid) { break } # Exit the loop if validation is successful

        Write-Information "${vtForegroundRed}${validationResult}${vtForegroundDefault}"
    }

    return $Value
}

Export-ModuleMember -Function Initialize-VersionSchema
Export-ModuleMember -Function Test-*
Export-ModuleMember -Function Request-*
Export-ModuleMember -Variable Version*
