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
# Outputs: [YamlCreate.ValidationResult]
####
function Test-PackageIdentifier {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [String] $PackageIdentifier
    )

    # Ensure the schema is loaded before proceeding
    Use-VersionSchema | Out-Null
    Write-Debug "Validating PackageIdentifier: $PackageIdentifier"

    $fieldMaxLength = $VersionSchema.properties.PackageIdentifier.maxLength
    $fieldPattern = $VersionSchema.properties.PackageIdentifier.pattern

    # Check for each validation rule on the field
    if ([String]::IsNullOrWhiteSpace($PackageIdentifier)) { return [ValidationResult]::new($false, 'Value cannot be empty') }
    if ($PackageIdentifier.Length -gt $fieldMaxLength) { return [ValidationResult]::new($false, "Value exceeds the maximum length of $fieldMaxLength characters") }
    if ($PackageIdentifier -notmatch $fieldPattern) { return [ValidationResult]::new($false, "Value does not match the required pattern: $fieldPattern") }

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
        $PackageIdentifier = Read-Host -Prompt 'Package Identifier'
        $validationResult = Test-PackageIdentifier -PackageIdentifier $PackageIdentifier

        if ($validationResult.IsValid) { break } # Exit the loop if validation is successful

        Write-Information "${vtForegroundRed}${validationResult}${vtForegroundDefault}"
    }

    return $PackageIdentifier
}

Export-ModuleMember -Function Initialize-VersionSchema
Export-ModuleMember -Function Test-*
Export-ModuleMember -Function Request-*
Export-ModuleMember -Variable Version*
