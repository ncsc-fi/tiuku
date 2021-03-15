[cmdletbinding()]
Param(
    [array]$EnabledModules = @(
        'Get-Metadata',
        'Get-PasswordPolicy',
        'Get-TombstoneLifetime',
        'Get-DomainAdmins',
        'Get-ServiceAccounts',
        'Get-DomainPolicies',
        'Get-UsersLastChangePasswordYearAgo',
        'Get-GPPPasswords',
        'Get-UconstrainedComputers',
        'Get-ForestTrusts',
        'Get-DomainTrusts',
        'Get-DomainOverview',
        'Get-KrbtgtUsers'
    ),
    $Url = "http://localhost:3000"
)

Write-Host "Active Directory tools"
Write-Host "                                                             by Traficom"
Write-Host ""

# Load 3rd party libs
. "$PSScriptRoot\powerview.ps1"
. "$PSScriptRoot\gpppasswords.ps1"

# Install RSAT AD tools
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    $required_capabilities = Get-WindowsCapability -Name 'Rsat.Activedirectory.*' -Online
    Write-Host "This script requires the following Windows capabilities:"
    Write-Host ""
    foreach ($c in $required_capabilities) {
        Write-Host $c.Name
    }
    Write-Host ""
    $answer = Read-Host "Would you like to install them now? [y/N]"
    if ($answer -eq "y") {
        $required_capabilities | Add-WindowsCapability -Online | Out-Null
    } else {
        exit
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

$datas = @{
    "ReportType" = "AD"
}

function Get-Metadata() {
    [hashtable]$return = @{}

    $return.Type = "Metadata"

    $return.Data = @{
        "Datetime" = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffffffZ")
    }
    
    return $return
}
function Get-DomainAdmins() {
    [hashtable]$return = @{}

    $return.Type = "DomainAdmins"

    $return.Data = @(Get-DomainGroupMember -Identity "Domain Admins" -Recurse)

    return $return
}
function Get-ForestTrusts() {
    [hashtable]$return = @{}

    $return.Type = "ForestTrust"

    $return.Data = Get-ForestTrust

    return $return
}
function Get-DomainTrusts() {
    [hashtable]$return = @{}

    $return.Type = "DomainTrust"

    $return.Data = Get-DomainTrust

    return $return
}
function Get-UsersLastChangePasswordYearAgo() {
    [hashtable]$return = @{}

    $return.Type = "UsersLastChangePasswordYearAgo"

    $Date = (Get-Date).AddYears(-1).ToFileTime()
    $return.Data = @(Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname, pwdlastset)

    return $return
}
function Get-GPPPasswords() {
    [hashtable]$return = @{}
    $return.Type = "GPPPasswords"

    $return.Data = @(Get-GPPPassword)

    return $return
}

function Get-ServiceAccounts() {
    [hashtable]$return = @{}

    $return.Type = "ServiceAccounts"

    $return.Data = @(Get-DomainUser -SPN)

    return $return
}
function Get-DomainPolicies() {
    [hashtable]$return = @{}

    $return.Type = "DomainPolicies"

    $return.Data = Get-DomainPolicyData -Policy Domain

    return $return
}

function Get-PasswordPolicy() {
    [hashtable]$return = @{}

    $return.Type = "PasswordPolicy"

    $return.Data =  Get-ADDefaultDomainPasswordPolicy
    return $return
}
function Get-TombstoneLifetime() {
    [hashtable]$return = @{}

    $return.Type = "TombstoneLifetime"

    $return.Data =  (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Properties TombstoneLifetime).TombstoneLifetime
    return $return
}
function Get-UconstrainedComputers() {
    [hashtable]$return = @{}

    $return.Type = "UnconstrainedComputers"

    $return.Data =  Get-DomainComputer -Unconstrained
    return $return
}

function Get-DomainOverview() {
    return @{
        Type = "DomainOverview"
        Data = @{
            UserCount = @(Get-ADUser -Filter *).Count
            DomainAdminGroupUserCount = @(Get-DomainGroupMember -Identity "Domain Admins" -Recurse).Count
            AdminCount1UserCount = @(Get-ADUser -Filter 'AdminCount -eq 1').Count
            GroupCount = @(Get-ADGroup -Filter *).Count
            ComputerCount = @(Get-ADComputer -Filter *).Count
            # Group-Object can return null if the array of computers is empty. Is this ever a problem in practice?
            ComputerCountByOs = @(Get-ADComputer -Filter * -Properties OperatingSystem) | Group-Object -Property OperatingSystem -NoElement
            ForestDomainCount = (Get-AdForest).Domains.Count
            OrganizationalUnitCount = @(Get-AdOrganizationalUnit -Filter *).Count
        }
    }
}

# Based on https://adsecurity.org/?p=483
function Get-KrbtgtUsers() {
    return @{
        Type = "KrbtgtUsers"
        Data = @(ForEach ($D in (Get-ADForest).Domains) {
            $DC = (Get-ADDomainController -Discover -Force -Service "PrimaryDC" -DomainName $D).HostName[0]
            @{
                Domain = $D
                User = Get-ADUser -Filter { Name -like "krbtgt*" } -Server $DC -Prop Created, PasswordLastSet, msDS-KeyVersionNumber, msDS-KrbTgtLinkBl | Select-Object -Property Name, Created, PasswordLastSet, msDS-KeyVersionNumber, msDS-KrbTgtLinkBl
            }
        })
    }
}

ForEach ($func in $EnabledModules) {
    Write-Host "Running function: $func..."
    $module = & $func
    $datas += @{$module.Type = $module.Data }
}

$data_json = $datas | ConvertTo-Json -Depth 10

$date = Get-Date -Format "yyyy_MM_dd_HHmm"
$report_file = "$PSScriptRoot\..\${date}_report.json"
$data_json | Out-File $report_file
Write-Host "Report saved to file: $report_file"
Write-Host "Press ENTER to close this window."
Read-Host
