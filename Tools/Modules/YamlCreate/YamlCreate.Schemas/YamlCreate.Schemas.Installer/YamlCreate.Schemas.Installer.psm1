[PSCustomObject] $InstallerSchema = $null
[PSCustomObject] $InstallerSchemaProperties = $null
[PSCustomObject] $InstallerSwitchProperties = $null
[PSCustomObject] $InstallerEntryProperties = $null
[PSCustomObject] $InstallerDependencyProperties = $null
[PSCustomObject] $AppsAndFeaturesEntryProperties = $null

####
# Description: Loads the installer schema into memory
# Inputs: Optional Override Schema Version
# Outputs: Void
####
function Initialize-InstallerSchema {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )
    Write-Debug "Loading installer schema for version $SchemaVersion"
    $script:InstallerSchema = Get-SchemaJson -SchemaType 'installer' -SchemaVersion $SchemaVersion | ConvertFrom-Json
    $script:InstallerSchemaProperties = $script:InstallerSchema.properties.PSObject.Properties.Name
    $script:InstallerSwitchProperties = $InstallerSchema.definitions.InstallerSwitches.properties.PSObject.Properties.Name
    $script:InstallerEntryProperties = $InstallerSchema.definitions.Installer.properties.PSObject.Properties.Name
    $script:InstallerDependencyProperties = $InstallerSchema.definitions.Dependencies.properties.PSObject.Properties.Name
    $script:AppsAndFeaturesEntryProperties = $InstallerSchema.definitions.AppsAndFeaturesEntry.properties.PSObject.Properties.Name
}

Export-ModuleMember -Function Initialize-InstallerSchema
Export-ModuleMember -Variable Installer*, AppsAndFeaturesEntryProperties
