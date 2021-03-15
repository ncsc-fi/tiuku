[CmdletBinding()]
Param(
    [array]$EnabledModules = @( 'Get-MFAStatus',
                                'Get-MailboxAuditLogStatus'
                                'Get-GlobalAdmins',
                                'Get-AzureDNSRecords',
                                'Get-MailboxForwardingRules'),
    $Url = "http://localhost:3000"
)

Write-Host "  _____  ________   ________.________   __                .__          "
Write-Host "  /     \ \_____  \ /  _____/|   ____/ _/  |_  ____   ____ |  |   ______"
Write-Host " /  \ /  \  _(__  </   __  \ |____  \  \   __\/  _ \ /  _ \|  |  /  ___/"
Write-Host "/    Y    \/       \  |__\  \/       \  |  | (  <_> |  <_> )  |__\___ \ "
Write-Host "\____|__  /______  /\_____  /______  /  |__|  \____/ \____/|____/____  >"
Write-Host "        \/       \/       \/       \/                                \/ "
Write-Host "                                                             by Traficom"
Write-Host ""

$datas = @{
    "ReportType" = "M365"
}

# Install deps
try {
    Import-Module -Name ExchangeOnlineManagement -ErrorAction Stop
    Import-Module -Name AzureAD -ErrorAction Stop
    Import-Module -Name MSOnline -ErrorAction Stop
    Import-Module -Name "Az.Dns" -ErrorAction Stop
} catch {
    Write-Host ""
    Write-Host "This script requires the following Powershell modules:"
    Write-Host ""
    Write-Host "EchangeOnlineManagement"
    Write-Host "AzureAD"
    Write-Host "MSOnline"
    Write-Host "Az.Dns"
    Write-Host ""

    $answer = Read-Host "Would you like to install them now? [y/N]"
    if ($answer -eq "y") {
        Write-Host "Installing modules...."

        Install-Module AzureAD -Force
        Install-Module ExchangeOnlineManagement -Force
        Install-Module MSonline -Force
        Install-Module -Name "Az.Dns" -Force
    } else {
        exit
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Import-Module AzureAD -ErrorAction Stop
    Import-Module MSOnline -ErrorAction Stop
    Import-Module -Name "Az.Dns" -ErrorAction Stop
}

Write-Host ""
$tenantId = Read-Host "Tenant ID? [If empty, uses the default tenant ID set to the login user account (submitted later)]"

if([string]::IsNullOrEmpty($tenantId)) {
    Connect-AzureAD
} else {
    Connect-AzureAD -Tenant $tenantId
}

#Connect & Login to ExchangeOnline (MFA)
$getsessions = Get-PSSession | Select-Object -Property State, Name
$isconnected = (@($getsessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
If ($isconnected -ne "True") {
    Connect-ExchangeOnline
}

# Check if already logged in
Get-MsolDomain -ErrorAction SilentlyContinue
if (!$?) {
    Connect-MsolService
}

Connect-AzAccount

function Get-Metadata() {
    [hashtable]$return = @{}

    $return.Type = "Metadata"

    $return.Data = @{
        "Datetime" = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffffffZ")
        }
    
    return $return
}

function Get-MFAStatus() {
    [hashtable]$return = @{}

    $return.Type = "Users"


    # Get MFA status of all users - Azure 365 permission: "Global Reader"
    $return.Data = @(Get-MsolUser -all | Where-Object { $_.UserType -eq "Member" } | Select-Object DisplayName, UserPrincipalName, StrongAuthenticationRequirements)
    
    return $return
}

function Get-MailboxAuditLogStatus {
    [hashtable]$return = @{}

    $return.Type = "Mailboxes"

    $return.Data = @(Get-EXOMailbox -ResultSize unlimited | Select-Object DisplayName, UserPrincipalName, AuditEnabled, DefaultAuditSet)

    return $return
}

function Get-MailboxForwardingRules {
    [hashtable]$return = @{}

    $return.Type = "MailboxesForwardingRules"

    $return.Data = @(Get-EXOMailbox -ResultSize unlimited | Select-Object DisplayName, UserPrincipalName, ForwardingAddress | Where-Object {$Null -ne $_.ForwardingAddress})

    return $return
}

function Get-GlobalAdmins() {
    [hashtable]$return = @{}

    $return.Type = "Globaladmins"

    $role = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq 'Company Administrator'}
    $return.Data = @(Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId)

    return $return
}

function Get-AzureDNSRecords {
    [hashtable]$return = @{}

    $return.Type = "AzureDNSRecords"

    $return.Data = @(Get-AzDnsZone | ForEach-Object { Get-AzDnsRecordSet -ZoneName $_.Name -ResourceGroupName $_.ResourceGroupName })
    return $return
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

Read-Host "Press ENTER to continue..."
