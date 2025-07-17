class ValidationResult {
  [bool] $IsValid
  [string] $Body

  ValidationResult([bool] $isValid, [string] $body) {
    $this.IsValid = $isValid
    $this.Body = $body
  }

  ValidationResult([bool] $isValid) {
    $this.IsValid = $isValid
    $this.Body = ''
  }

  [string]ToString() {
    if ($this.IsValid) {
      return "Validation succeeded: $($this.Body)"
    } else {
      return "Validation failed: $($this.Body)"
    }
  }

  [bool]Equals([object] $obj) {
    if ($obj -is [ValidationResult]) {
      return $this.IsValid -eq $obj.IsValid -and $this.Body -eq $obj.Body
    }
    return $false
  }
}
