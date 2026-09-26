$base = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$profiles = Get-ChildItem $base -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' }
foreach ($profile in $profiles) {
    $prefsPath = "$base\$($profile.Name)\Preferences"
    if (Test-Path $prefsPath) {
        $prefs = Get-Content $prefsPath -Raw | ConvertFrom-Json
        $settings = $prefs.extensions.settings
        foreach ($prop in $settings.PSObject.Properties) {
            $path = $prop.Value.path
            if ($path -and ($path -like '*WebExtention*' -or $path -like '*CyberSec*')) {
                Write-Output "FOUND in $($profile.Name): $($prop.Name) -> $path"
            }
        }
    }
}
Write-Output "Done scanning profiles."
