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

  $script:HttpClient = New-Object System.Net.Http.HttpClient

  Write-Debug "Attempting to fetch content from $URL"
  # Check if the URL is valid before trying to download
  if ([String]::IsNullOrWhiteSpace($URL)) {
    $response = @{StatusCode = 400 }
  } else {
    $response = Invoke-WebRequest -Uri $URL -Method Head -ErrorAction SilentlyContinue
  }

  if ($response.StatusCode -ne 200) {
    Write-Debug "Fetching remote content from $URL returned status code $($response.StatusCode)"
    return $null
  }

  # If a path was specified, store it at that path; Otherwise use the temp folder
  if ($OutputPath) {
    $localFile = [System.IO.FileInfo]::new($OutputPath)
  } else {
    $localFile = New-TemporaryFile
  }

  Write-Debug "Remote content will be stored at $($localFile.FullName)"

  try {
    $downloadTask = $script:HttpClient.GetByteArrayAsync($URL)
    [System.IO.File]::WriteAllBytes($localfile.FullName, $downloadTask.Result)
  } catch {
    # If the download fails, write a zero-byte file anyways
    $null | Out-File $localFile.FullName
  } finally {
    if ($script:HttpClient) {
      $script:HttpClient.Dispose()
    }
  }

  # If the raw content was requested, return the content, otherwise, return the FileInfo object
  if ($Raw) {
    $remoteContent = Get-Content -Path $localFile.FullName
    Write-Debug "Removing temporary file $($localFile.FullName) after fetching remote content"
    Remove-Item -Path $localFile.FullName -Force -ErrorAction 'SilentlyContinue'
    return $remoteContent
  } else {
    return $localFile
  }
}

Export-ModuleMember -Function Get-RemoteContent

# # Import all sub-modules
# $script:moduleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Get-ChildItem -Path $script:moduleRoot -Recurse -Depth 1 -Filter '*.psd1' | ForEach-Object {
#   if ($_.Name -eq 'YamlCreate.psd1') {
#     # Skip the main module manifest as it is already handled
#     return
#   }
#   $moduleFolder = Join-Path -Path $script:moduleRoot -ChildPath $_.Directory.Name
#   $moduleFile = Join-Path -Path $moduleFolder -ChildPath $_.Name
#   Import-Module $moduleFile -Force -Scope Global -ErrorAction 'Stop'
# }

# Import all sub-modules
$script:moduleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-ChildItem -Path $script:moduleRoot -Recurse -Depth 1 -Filter '*.psd1' | ForEach-Object {
  if ($_.Name -eq 'YamlCreate.psd1') {
    # Skip the main module manifest as it is already handled
    return
  }
  $moduleFolder = Join-Path -Path $script:moduleRoot -ChildPath $_.Directory.Name
  $moduleFile = Join-Path -Path $moduleFolder -ChildPath $_.Name
  Import-Module $moduleFile -Force -Scope Local -ErrorAction 'Stop'

  # Because the module is imported to the local scope, we need to export the functions up to the calling scope
  (Get-Module $_.BaseName).ExportedFunctions.Keys | ForEach-Object {
    Export-ModuleMember -Function $_
  }

  # Because the module is imported to the local scope, we need to export the variables up to the calling scope
  (Get-Module $_.BaseName).ExportedVariables.Keys | ForEach-Object {
    Export-ModuleMember -Variable $_
  }
}
