function Get-JEAAudit {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        WinRmState            = $null
        HasJEASessionConfig   = $false
        SessionConfigurations = @()
        RoleCapabilityFiles   = @()
        PSModulePaths         = @()
        Comment               = $null
        Recommendation        = $null
    }

    $winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

    if (-not $winrm) {
        $result.WinRmState     = 'NotInstalled'
        $result.Comment        = 'Le service WinRM n''est pas installe ou accessible sur cet hote.'
        $result.Recommendation = 'Si JEA / PowerShell remoting est requis, installez et configurez WinRM de maniere securisee (HTTPS, points de terminaison restreints, JEA).'
        return $result
    }

    $result.WinRmState = $winrm.Status.ToString()

    if ($winrm.Status -ne 'Running') {
        $result.WinRmState     = 'Stopped'
        $result.Comment        = 'Le service WinRM est present mais non actif; les points de terminaison JEA ne seront pas utilisables.'
        $result.Recommendation = 'Demarrez et securisez WinRM uniquement sur les systemes ou l''administration a distance et JEA sont requis.'
        return $result
    }

    $sessionConfigs = Get-PSSessionConfiguration -ErrorAction SilentlyContinue |
                      Select-Object Name, Permission

    if ($sessionConfigs) {
        $result.HasJEASessionConfig   = $true
        $result.SessionConfigurations = $sessionConfigs
        $result.Comment               = 'Un ou plusieurs configurations de session PowerShell sont enregistrees; certaines peuvent etre des points de terminaison JEA.'
        $result.Recommendation        = 'Examinez les configurations de session JEA pour vous assurer qu''elles exposent uniquement les cmdlets requises et sont restreintes aux groupes appropriés.'
    }
    else {
        $result.HasJEASessionConfig   = $false
        $result.Comment               = 'Aucune configuration de session PowerShell personnalisée trouvée; JEA ne semble pas être configuré.'
        $result.Recommendation        = 'Considerez de deployer des points de terminaison JEA pour les taches privilegiees au lieu d''accorder un acces complet a l''administration a distance.'
    }

    $psModulePath = $env:PSModulePath -split ';'
    $result.PSModulePaths = $psModulePath

    $files = @()
    foreach ($p in $psModulePath) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (Test-Path -LiteralPath $p) {
            $files += Get-ChildItem -Path $p -Recurse -Filter '*.psrc' -ErrorAction SilentlyContinue
        }
    }

    if ($files) {
        $result.RoleCapabilityFiles = $files.FullName
    }

    return $result
}

