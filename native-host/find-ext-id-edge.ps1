$base = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$prefFiles = Get-ChildItem $base -Recurse -Filter "Preferences" -ErrorAction SilentlyContinue
foreach ($pf in $prefFiles) {
    $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match 'WebExtention' -or $content -match 'CyberSec') {
        Write-Output "Found reference in: $($pf.FullName)"
        $prefs = $content | ConvertFrom-Json
        try {
            $settings = $prefs.extensions.settings
            foreach ($prop in $settings.PSObject.Properties) {
                $path = $prop.Value.path
                if ($path -and ($path -like '*WebExtention*' -or $path -like '*CyberSec*')) {
                    Write-Output "  Extension ID: $($prop.Name)"
                    Write-Output "  Path: $path"
                }
            }
        } catch {
            Write-Output "  (Could not parse extensions.settings)"
        }
    }
}

$spFiles = Get-ChildItem $base -Recurse -Filter "Secure Preferences" -ErrorAction SilentlyContinue
foreach ($sf in $spFiles) {
    $content = Get-Content $sf.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match 'WebExtention' -or $content -match 'CyberSec') {
        Write-Output "Found in Secure Preferences: $($sf.FullName)"
        $prefs = $content | ConvertFrom-Json
        try {
            $settings = $prefs.extensions.settings
            foreach ($prop in $settings.PSObject.Properties) {
                $path = $prop.Value.path
                if ($path -and ($path -like '*WebExtention*' -or $path -like '*CyberSec*')) {
                    Write-Output "  Extension ID: $($prop.Name)"
                    Write-Output "  Path: $path"
                }
            }
        } catch {
            Write-Output "  (Could not parse)"
        }
    }
}

Write-Output "Done."
