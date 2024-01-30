# This script provides several functions for interacting with the WinGet pre-indexed package default source
# It is intended to be dot sourced such that the functions can be called independently

$global:WingetIsInstalled = ((Get-Command 'winget' -ErrorAction SilentlyContinue) -is [System.Object])

function Get-SQLiteInstallFolder {
  if ([System.Environment]::Is64BitProcess) { return Join-Path $env:LOCALAPPDATA -ChildPath 'sqLite-64' }
  return Join-Path $env:LOCALAPPDATA -ChildPath 'sqLite-32'
}

function Test-SQLiteInstall {
  $installFolder = Get-SQLiteInstallFolder
  if (!(Test-Path $installFolder)) { return $false }
  $dynamicLibrary = Get-ChildItem $installFolder -Filter 'System.Data.SQLite.dll'
  if ($null -eq $dynamicLibrary) { return $false }
  return $dynamicLibrary
}

function Install-SQLite {
  $dynamicLibrary = Test-SQLiteInstall
  if ($dynamicLibrary) { return $dynamicLibrary }
  $installFolder = Get-SQLiteInstallFolder
  if ([System.Environment]::Is64BitProcess) {
    $downloadUrl = 'https://system.data.sqlite.org/blobs/1.0.118.0/sqlite-netFx45-binary-x64-2012-1.0.118.0.zip'
    $sha1 = '3ef1532e1457626efb5b411973ac81f7e548c03b'
  } else {
    $downloadUrl = 'https://system.data.sqlite.org/blobs/1.0.118.0/sqlite-netFx45-binary-Win32-2012-1.0.118.0.zip'
    $sha1 = 'a2b4d44cafe4dd4f03c2900d8039307c7c0e4585'
  }

  Write-Verbose "Installing SQLite from $downloadUrl"
  $newFile = New-TemporaryFile
  $zipLocation = Join-Path $installFolder -ChildPath 'sqlite.zip'
  Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing -OutFile $newfile.FullName
  if ($(Get-FileHash -Path $newFile.FullName -Algorithm SHA1).hash -ne $sha1) {
    Remove-Item $newFile.FullName -Force
    throw 'SQLite Binaries failed hash check'
  }
  if (!(Test-Path $installFolder)) { New-Item -ItemType Directory -Path $installFolder | Out-Null }
  Move-Item -Path $newFile.FullName -Destination $zipLocation -Force
  $zipFile = Get-Item $zipLocation
  Write-Verbose "Downloaded SQLite to $zipLocation"
  Write-Verbose 'Extracting SQLite . . .'
  Expand-Archive -Path $zipFile.FullName -DestinationPath $installFolder
  Write-Verbose "SQLite extracted to $installFolder"
  $dynamicLibrary = Get-ChildItem $installFolder -Filter 'System.Data.SQLite.dll'
  if ($null -eq $dynamicLibrary) { return $false }
  return $dynamicLibrary
}

function Initialize-SQLite {
  Write-Verbose 'Initializing SQLite . . . '
  $dynamicLibrary = Install-SQLite
  if ($dynamicLibrary) {
    [Reflection.Assembly]::LoadFile($dynamicLibrary.FullName) | Out-Null
    Write-Verbose 'SQLite Initialized!'
    return $true
  }
  return $false
}

function Get-WinGetSourceLocation {
  return $(Join-Path $env:TEMP -ChildPath 'source.msix')
}

function Get-ExpandedSourceLocation {
  return $(Join-Path $env:TEMP -ChildPath 'source')
}

function Get-WinGetSourceFile {
  $sourceLocation = Get-WinGetSourceLocation
  Write-Verbose 'Downloading source.msix . . . '
  Invoke-WebRequest -Uri 'https://cdn.winget.microsoft.com/cache/source.msix' -UseBasicParsing -OutFile $sourceLocation
  Write-Verbose "Downloaded source.msix to $sourceLocation"
  return Get-Item -Path $sourceLocation
}

function Expand-WinGetSourceFile {
  $sourcePath = Get-WinGetSourceLocation
  if (!(Test-Path $sourcePath)) { Get-WinGetSourceFile }
  $zipPath = $(Join-Path $env:TEMP -ChildPath 'source.zip')
  $extractedPath = Get-ExpandedSourceLocation
  Write-Verbose "Extracting source.msix to $extractedPath . . ."
  Remove-Item $zipPath -Force -ErrorAction 'silentlyContinue' # silentlyContinue in case the item does not exist
  Remove-Item $extractedPath -Recurse -Force -ErrorAction 'silentlyContinue' # silentlyContinue in case the item does not exist
  Copy-Item -Path $sourcePath -Destination $zipPath
  Expand-Archive -Path $zipPath -DestinationPath $extractedPath -Force
  Remove-Item $zipPath -Force
  Write-Verbose "Sucessfully extracted source.msix into $extractedPath"
  return Get-Item -Path $extractedPath
}

function Get-WinGetDatabase {
  $extractedPath = Get-ExpandedSourceLocation
  if (!(Test-Path $extractedPath)) { Expand-WinGetSourceFile }
  $index = Get-ChildItem $extractedPath -Recurse -Filter 'index.db'
  return $index
}

function Mount-WinGetDatabase {
  if (!(Initialize-SQLite)) { return $false }
  $wingetDatabase = Get-WinGetDatabase
  $global:WinGetSQLiteConnection = New-Object System.Data.SQLite.SQLiteConnection
  $global:WinGetSQLiteConnection.ConnectionString = "Data Source=$($wingetDatabase.FullName)"
  $global:WinGetSQLiteConnection.Open()
  return $true
}

function Dismount-WinGetDatabase {
  if (!$WinGetSQLiteConnection) { return $false }
  $global:WinGetSQLiteConnection.Close()
  $global:WinGetSQLiteConnection.Dispose()
  [System.GC]::Collect()
  [System.GC]::WaitForPendingFinalizers()
  return $true
}

function Update-WinGetDatabase {
  Dismount-WinGetDatabase | Out-Null
  Get-WinGetSourceFile | Out-Null
  Expand-WinGetSourceFile | Out-Null
  Mount-WinGetDatabase
}

function Find-WinGetPackageIdentifier {
  [CmdletBinding()]
  param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String] $Query,
    [Parameter()]
    [ValidateSet('Substring', 'CaseInsensitive', 'Exact')]
    [String] $MatchType = 'Substring',
    [Parameter()]
    [ValidateNotNull()]
    [System.Data.SQLite.SQLiteConnection] $Connection = $global:WinGetSQLiteConnection
  )

  $findCommand = $Connection.CreateCommand()
  $findCommand.CommandType = [System.Data.CommandType]::Text
  $findCommand.CommandText = 'SELECT * FROM ids WHERE '
  switch ($MatchType) {
    'CaseInsensitive' { $findCommand.CommandText += "id like '$Query'" }
    'Exact' { $findCommand.CommandText += "id = '$Query'" }
    Default { $findCommand.CommandText += "id like '%$Query%'" }
  }
  $reader = $findCommand.ExecuteReader()
  $reader.GetValues() | Out-Null
  $ids = @()
  while ($reader.HasRows) {
    if ($reader.Read()) {
      $ids += $reader['id']
    }
  }
  $reader.Close()
  $reader.Dispose()
  $findCommand.Dispose()
  return $ids
}
