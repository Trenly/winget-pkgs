$VersionSchema = $null

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
}

Export-ModuleMember -Function Initialize-VersionSchema
Export-ModuleMember -Variable VersionSchema
