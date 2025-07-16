$DefaultSchemaVersion = [System.Version]::new(1, 10, 0); $DefaultSchemaVersion | Out-Null

enum SchemaType {
    version
    installer
    locale
    defaultLocale
}

####
# Description: Returns the URL for a given schema file
# Inputs: Schema Type, Optional Override Schema Version
# Outputs: URI
####
function Get-SchemaUrl {
    param (
        [Parameter(Mandatory = $true)]
        [SchemaType] $SchemaType,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )

    # If no schema version is provided, use the default version
    # This must be done here to account for the case where the schema version is passed as null
    if (!$SchemaVersion) {
        $SchemaVersion = $DefaultSchemaVersion
    }

    $akaMsLink = "https://aka.ms/winget-manifest.$($SchemaType.ToString()).$SchemaVersion.schema.json"
    Write-Debug "Checking schema URL: $akaMsLink"

    # Check if an aka.ms link is available for the schema
    $script:UseDirectSchemaLink = $env:GITHUB_ACTIONS -or (Invoke-WebRequest $akaMsLink -UseBasicParsing).Content -match '<!doctype html>'
    if ($useDirectSchemaLink) {
        return [uri]::new("https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v$SchemaVersion/manifest.$($SchemaType.ToString()).$SchemaVersion.json")
    }

    return [uri]::new($akaMsLink)
}

####
# Description: Returns the JSON for a given schema file
# Inputs: Schema Type, Optional Override Schema Version
# Outputs: JSON Content
####
function Get-SchemaJson {
    param (
        [Parameter(Mandatory = $true)]
        [SchemaType] $SchemaType,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Version] $SchemaVersion
    )

    $SchemaUrl = Get-SchemaUrl -SchemaType $SchemaType -SchemaVersion $SchemaVersion
    return Get-RemoteContent -URL $SchemaUrl -Raw
}

Export-ModuleMember -Function Get-SchemaUrl
Export-ModuleMember -Function Get-SchemaJson
Export-ModuleMember -Variable DefaultSchemaVersion


# Import all sub-modules
$script:moduleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Warning "Importing sub-modules from $script:moduleRoot"
Get-ChildItem -Path $script:moduleRoot -Recurse -Depth 1 -Filter '*.psd1'| ForEach-Object {
    Write-Warning "Checking $($_.Name)"
    if ($_.Name -eq 'YamlCreate.Schemas.psd1') {
        # Skip the main module manifest as it is already handled
        return
    }
    $moduleFolder = Join-Path -Path $script:moduleRoot -ChildPath $_.Directory.Name
    $moduleFile = Join-Path -Path $moduleFolder -ChildPath $_.Name
    Import-Module $moduleFile -Force -Scope Global -ErrorAction 'Stop'
}
