$LocaleSchema = $null
$DefaultLocaleSchema = $null
[PSCustomObject] $LocaleSchemaProperties = $null
[PSCustomObject] $DefaultLocaleSchemaProperties = $null

####
# Description: Loads the locale schema into memory
# Inputs: Optional Override Schema Version
# Outputs: Void
####
function Initialize-LocaleSchema {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )
    Write-Debug "Loading locale schema for version $SchemaVersion"
    $script:LocaleSchema = Get-SchemaJson -SchemaType 'locale' -SchemaVersion $SchemaVersion | ConvertFrom-Json
    $script:LocaleSchemaProperties = $script:LocaleSchema.properties.PSObject.Properties.Name
}

####
# Description: Loads the defaultLocale schema into memory
# Inputs: Optional Override Schema Version
# Outputs: Void
####
function Initialize-DefaultLocaleSchema {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )
    Write-Debug "Loading defaultLocale schema for version $SchemaVersion"
    $script:DefaultLocaleSchema = Get-SchemaJson -SchemaType 'defaultLocale' -SchemaVersion $SchemaVersion | ConvertFrom-Json
    $script:DefaultLocaleSchemaProperties = $script:DefaultLocaleSchema.properties.PSObject.Properties.Name
}

Export-ModuleMember -Function Initialize-LocaleSchema
Export-ModuleMember -Function Initialize-DefaultLocaleSchema
Export-ModuleMember -Variable Locale*
Export-ModuleMember -Variable DefaultLocale*
