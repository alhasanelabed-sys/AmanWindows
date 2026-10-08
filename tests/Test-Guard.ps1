#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RootDirectory = (Split-Path -Parent $PSScriptRoot)
)

# No Pester or administrative privileges are required. These tests exercise
# fixture-driven public functions. Action tests replace every native mutator
# with a module-scoped stub and use fresh imports; real Windows settings and
# native Defender scans are never changed by this harness.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$script:Passed = 0
$script:Failed = 0

function Assert-Guard {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-GuardThrows {
    param([scriptblock]$Operation, [string]$Message, [string]$ExpectedMessagePattern = '')
    $didThrow = $false
    $actualMessage = ''
    try { & $Operation | Out-Null } catch { $didThrow = $true; $actualMessage = $_.Exception.Message }
    Assert-Guard -Condition $didThrow -Message $Message
    if ($ExpectedMessagePattern) {
        Assert-Guard ($actualMessage -match $ExpectedMessagePattern) ($Message + ' Unexpected error: ' + $actualMessage)
    }
}

function Test-GuardCase {
    param([string]$Name, [scriptblock]$Test)
    try {
        & $Test
        $script:Passed++
        Write-Host ('PASS: {0}' -f $Name)
    } catch {
        $script:Failed++
        Write-Host ('FAIL: {0}: {1}' -f $Name, $_.Exception.Message)
    }
}

$corePath = Join-Path $RootDirectory 'Guard.Core.psm1'
$reportPath = Join-Path $RootDirectory 'Report.ps1'
if (-not (Test-Path -LiteralPath $corePath -PathType Leaf)) {
    throw ('Core module is missing: {0}' -f $corePath)
}
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    throw ('Report exporter is missing: {0}' -f $reportPath)
}

Import-Module $corePath -Force
. $reportPath

function New-GuardFixtureSections {
    $sections = @{}
    foreach ($name in @('System', 'Defender', 'Detections', 'Firewall', 'RemoteAccess', 'SMB', 'UAC', 'Network', 'Startup', 'Logons', 'Updates')) {
        $sections[$name] = [pscustomobject]@{ Available = $true; Error = $null; Data = $null }
    }
    $sections.System.Data = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; Version = '10.0'; Build = 26100; Release = '24H2'; UBR = 5000; Edition = 'Professional' }
    $sections.Defender.Data = [pscustomobject]@{
        AMRunningMode = 'Normal'; AMServiceEnabled = $true; AntivirusEnabled = $true
        RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 0
        AntivirusSignatureLastUpdated = '2026-10-08T08:00:00Z'; IsTamperProtected = $true
    }
    $sections.Detections.Data = @()
    $sections.Firewall.Data = @(
        [pscustomobject]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block' }
        [pscustomobject]@{ Name = 'Private'; Enabled = $true; DefaultInboundAction = 'Block' }
        [pscustomobject]@{ Name = 'Public'; Enabled = $true; DefaultInboundAction = 'Block' }
    )
    $sections.RemoteAccess.Data = [pscustomobject]@{ RdpEnabled = $false; NlaRequired = $true; PolicySource = 'Local' }
    $sections.SMB.Data = [pscustomobject]@{ FeatureState = 'Disabled' }
    $sections.UAC.Data = [pscustomobject]@{ Enabled = $true }
    $sections.Network.Data = [pscustomobject]@{ Tcp = @(); Udp = @() }
    $sections.Startup.Data = @()
    $sections.Logons.Data = [pscustomobject]@{ Events = @(); Truncated = $false; LookbackHours = 24; Limit = 2000 }
    $sections.Updates.Data = @([pscustomobject]@{ HotFixID = 'KB0000001'; InstalledOnUtc = '2026-10-08T00:00:00Z' })
    return $sections
}

function New-GuardFixtureLogon {
    param([int]$EventId, [int]$LogonType, [string]$IpAddress = '198.51.100.12')
    return [pscustomobject]@{
        EventId = $EventId; TimeUtc = '2026-10-08T08:00:00Z'; LogonType = $LogonType
        User = 'fixture-user'; Domain = 'TEST'; IpAddress = $IpAddress
    }
}

function Invoke-GuardIsolatedModuleTest {
    param([scriptblock]$Configure, [scriptblock]$Operation, [AllowNull()][object]$Context = $null)
    # Restore the original module in finally, even when an assertion fails.
    Remove-Module 'Guard.Core' -ErrorAction SilentlyContinue
    $module = Import-Module $corePath -Force -PassThru
    try {
        & $module {
            $script:TestMutationCount = 0
            $script:TestSawPreparedReceipt = $false
            function script:Assert-GuardAdmin { }
            function script:Set-NetFirewallProfile { throw 'Unconfigured test-only firewall mutation stub.' }
            function script:Set-MpPreference { throw 'Unconfigured test-only Defender mutation stub.' }
            function script:Invoke-CimMethod { throw 'Unconfigured test-only CIM mutation stub.' }
            function script:Start-MpScan { throw 'Unconfigured test-only Defender scan stub.' }
            function script:Update-MpSignature { throw 'Unconfigured test-only Defender update stub.' }
        }
        & $module $Configure $Context
        & $Operation $module
    } finally {
        Remove-Module 'Guard.Core' -ErrorAction SilentlyContinue
        Import-Module $corePath -Force
    }
}

Test-GuardCase 'Missing telemetry is unknown, never silently healthy' {
    $findings = @(Get-GuardFindings -Sections @{} -IsAdmin $false)
    foreach ($name in @('System', 'Defender', 'Detections', 'Firewall', 'RemoteAccess', 'SMB', 'UAC', 'Network', 'Startup', 'Logons', 'Updates')) {
        $matching = @($findings | Where-Object { $_.Id -eq ('unavailable-' + $name) })
        Assert-Guard ($matching.Count -eq 1) ('Missing section needs exactly one availability finding: ' + $name)
        Assert-Guard ($matching[0].Severity -eq 'Unknown') ('Missing section was not unknown: ' + $name)
    }
}

Test-GuardCase 'Failed firewall collection stays unknown' {
    $sections = New-GuardFixtureSections
    $sections.Firewall = [pscustomobject]@{ Available = $false; Error = 'Access denied'; Data = $null }
    $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $false)
    Assert-Guard (@($findings | Where-Object { $_.Id -eq 'unavailable-Firewall' -and $_.Severity -eq 'Unknown' }).Count -eq 1) 'Unavailable firewall was not marked unknown.'
    Assert-Guard (@($findings | Where-Object { $_.Id -eq 'firewall-disabled' }).Count -eq 0) 'Failed telemetry was incorrectly called a disabled firewall.'
}

Test-GuardCase 'Partial protection data stays unknown rather than falsely disabled' {
    foreach ($name in @('Defender', 'UAC')) {
        foreach ($data in @([pscustomobject]@{}, $null)) {
            $sections = New-GuardFixtureSections
            $sections[$name].Data = $data
            $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
            Assert-Guard (@($findings | Where-Object { $_.Id -eq ('unavailable-' + $name) -and $_.Severity -eq 'Unknown' }).Count -eq 1) ('Missing protection fields were not marked unknown: ' + $name)
            Assert-Guard (@($findings | Where-Object { $_.Id -in @('defender-realtime-disabled', 'uac-disabled') }).Count -eq 0) 'Missing protection fields incorrectly produced a disabled-protection accusation.'
        }
    }
}

Test-GuardCase 'Defender passive mode does not claim disabled real-time protection' {
    $sections = New-GuardFixtureSections
    $sections.Defender.Data.AMRunningMode = 'Passive Mode'
    $sections.Defender.Data.RealTimeProtectionEnabled = $false
    $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    Assert-Guard (@($findings | Where-Object { $_.Id -eq 'defender-realtime-disabled' }).Count -eq 0) 'Passive Defender mode was treated as an actionable disabled protection setting.'
}

Test-GuardCase 'Active Defender protection gap is actionable' {
    $sections = New-GuardFixtureSections
    $sections.Defender.Data.RealTimeProtectionEnabled = $false
    $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    $matching = @($findings | Where-Object { $_.Id -eq 'defender-realtime-disabled' })
    Assert-Guard ($matching.Count -eq 1) 'Normal mode real-time protection gap was not reported.'
    Assert-Guard ($matching[0].ActionId -eq 'EnableRealtime') 'The real-time finding does not point to the approved repair.'
}

Test-GuardCase 'An available empty Defender detection pipeline is a valid clean snapshot' {
    $sections = New-GuardFixtureSections
    $sections.Detections.Data = $null
    $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    Assert-Guard (@($findings | Where-Object { $_.Id -eq 'detections-active' }).Count -eq 0) 'An empty native detection result was incorrectly reported as an active threat.'
}

Test-GuardCase 'Full collector handles clean native empty pipelines without losing telemetry availability' {
    $context = [pscustomobject]@{ Defender = (New-GuardFixtureSections).Defender.Data }
    Invoke-GuardIsolatedModuleTest -Context $context -Configure {
        param($context)
        $script:TestCleanDefender = $context.Defender
        function script:Test-GuardWindows { return $true }
        function script:Test-GuardAdmin { return $true }
        function script:Get-CimInstance {
            [CmdletBinding()] param($ClassName)
            switch ($ClassName) {
                'Win32_OperatingSystem' { return [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; Version = '10.0'; BuildNumber = 26100 } }
                'Win32_Process' { return @() }
                'Win32_StartupCommand' { return @() }
                default { throw ('Unexpected CIM class in isolated test: ' + $ClassName) }
            }
        }
        function script:Get-ItemProperty {
            [CmdletBinding()] param($Path, $Name)
            switch ($Path) {
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' { return [pscustomobject]@{ DisplayVersion = '24H2'; UBR = 5000; EditionID = 'Professional' } }
                'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' { return [pscustomobject]@{ fDenyTSConnections = 1 } }
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' { return [pscustomobject]@{ EnableLUA = 1 } }
                default { throw ('Unexpected registry read in isolated test: ' + $Path) }
            }
        }
        function script:Get-MpComputerStatus { [CmdletBinding()] param() return $script:TestCleanDefender }
        function script:Get-MpThreat { [CmdletBinding()] param() return @() }
        function script:Get-NetFirewallProfile {
            [CmdletBinding()] param($PolicyStore)
            return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' } })
        }
        function script:Get-WindowsOptionalFeature { [CmdletBinding()] param([switch]$Online, $FeatureName) return [pscustomobject]@{ State = 'Disabled' } }
        function script:Get-NetTCPConnection { [CmdletBinding()] param() return @() }
        function script:Get-NetUDPEndpoint { [CmdletBinding()] param() return @() }
        function script:Get-WinEvent {
            [CmdletBinding()] param($FilterHashtable, $MaxEvents)
            $record = [Management.Automation.ErrorRecord]::new([Exception]::new('No fixture events.'), 'NoMatchingEventsFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            $PSCmdlet.ThrowTerminatingError($record)
        }
        function script:Get-HotFix { [CmdletBinding()] param() return @() }
        function script:Get-GuardRdpSetting { throw 'RDP is disabled in this fixture and must not query settings.' }
    } -Operation {
        param($module)
        $report = Get-GuardReport
        Assert-Guard ($report.Sections.Count -eq 11) 'The integrated collector did not preserve every expected section.'
        foreach ($section in $report.Sections.Values) { Assert-Guard $section.Available ('A mocked clean native section became unavailable: ' + $section.Error) }
        Assert-Guard ($report.IsAdmin -eq $true) 'The integrated report lost the explicit privilege result.'
        Assert-Guard (@($report.Findings | Where-Object { $_.Id -eq 'detections-active' -or $_.Severity -in @('High', 'Medium') }).Count -eq 0) 'A mocked clean device was incorrectly accused of active threats or protection gaps.'
        Assert-Guard (@($report.Sections.Logons.Data.Events).Count -eq 0) 'A no-matching-events native result did not become an empty event list.'
        $mutations = & $module { $script:TestMutationCount }
        Assert-Guard ($mutations -eq 0) 'Read-only collection performed a fake mutation.'
    }
}

Test-GuardCase 'Public network peer does not become an intruder verdict' {
    $sections = New-GuardFixtureSections
    $sections.Network.Data.Tcp = @([pscustomobject]@{
        LocalAddress = '192.168.1.7'; LocalPort = 50000; RemoteAddress = '8.8.8.8'; RemotePort = 443
        State = 'Established'; OwningProcess = 1234; ProcessName = 'browser'; Path = 'C:\Program Files\Browser\browser.exe'
    })
    $baseline = @(Get-GuardFindings -Sections (New-GuardFixtureSections) -IsAdmin $true | Where-Object { $_.Severity -in @('High', 'Medium') } | ForEach-Object { $_.Id })
    $withPeer = @(Get-GuardFindings -Sections $sections -IsAdmin $true | Where-Object { $_.Severity -in @('High', 'Medium') } | ForEach-Object { $_.Id })
    Assert-Guard (($baseline -join '|') -eq ($withPeer -join '|')) 'An ordinary established public TLS connection introduced a security accusation.'
}

Test-GuardCase 'Routine 4624 logon does not become an intrusion verdict' {
    $sections = New-GuardFixtureSections
    $sections.Logons.Data.Events = @(New-GuardFixtureLogon -EventId 4624 -LogonType 3 -IpAddress '192.168.1.10')
    $baseline = @(Get-GuardFindings -Sections (New-GuardFixtureSections) -IsAdmin $true | Where-Object { $_.Severity -in @('High', 'Medium') } | ForEach-Object { $_.Id })
    $withLogon = @(Get-GuardFindings -Sections $sections -IsAdmin $true | Where-Object { $_.Severity -in @('High', 'Medium') } | ForEach-Object { $_.Id })
    Assert-Guard (($baseline -join '|') -eq ($withLogon -join '|')) 'A successful routine network logon introduced a security accusation.'
}

Test-GuardCase 'Repeated failed login threshold respects the ten-event boundary' {
    $sections = New-GuardFixtureSections
    $sections.Logons.Data.Events = @(1..9 | ForEach-Object { New-GuardFixtureLogon -EventId 4625 -LogonType 3 })
    $nine = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    Assert-Guard (@($nine | Where-Object { $_.Id -eq 'logon-failures-198.51.100.12' }).Count -eq 0) 'Nine events incorrectly reached the documented ten-event threshold.'
    $sections.Logons.Data.Events = @(1..10 | ForEach-Object { New-GuardFixtureLogon -EventId 4625 -LogonType 3 })
    $ten = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    Assert-Guard (@($ten | Where-Object { $_.Id -eq 'logon-failures-198.51.100.12' }).Count -eq 1) 'Ten failed events from one peer were not reported exactly once.'
    $sections.Logons.Data.Events = @(
        1..5 | ForEach-Object { New-GuardFixtureLogon -EventId 4625 -LogonType 3 -IpAddress '198.51.100.12' }
        1..5 | ForEach-Object { New-GuardFixtureLogon -EventId 4625 -LogonType 3 -IpAddress '198.51.100.13' }
    )
    $split = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    Assert-Guard (@($split | Where-Object { $_.Id -like 'logon-failures-*' }).Count -eq 0) 'Failed logons from separate peers were incorrectly combined into one peer threshold.'
}

Test-GuardCase 'Successful RDP logons are evidence for review, not a proven attack' {
    $sections = New-GuardFixtureSections
    $sections.Logons.Data.Events = @(New-GuardFixtureLogon -EventId 4624 -LogonType 10)
    $findings = @(Get-GuardFindings -Sections $sections -IsAdmin $true)
    $matching = @($findings | Where-Object { $_.Id -eq 'rdp-logons' })
    Assert-Guard ($matching.Count -eq 1) 'RDP evidence was not shown.'
    Assert-Guard ($matching[0].Severity -eq 'Info') 'A successful RDP logon was treated as a proven malicious event.'
}

Test-GuardCase 'Event XML parses named fields without positional assumptions' {
    $eventXml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-10-08T08:00:00.0000000Z"/><EventRecordID>987</EventRecordID><Computer>DESKTOP-TEST</Computer></System><EventData><Data Name="IpAddress">2001:db8::12</Data><Data Name="UnusedField">irrelevant</Data><Data Name="TargetDomainName">TEST</Data><Data Name="TargetUserName">fixture-user</Data><Data Name="LogonType">3</Data></EventData></Event>
'@
    $event = ConvertTo-GuardEventRecord -EventXml $eventXml
    Assert-Guard ([int]$event.EventId -eq 4624) 'Event ID was not parsed correctly.'
    Assert-Guard ([int]$event.LogonType -eq 3) 'Logon type was not parsed correctly.'
    Assert-Guard ($event.User -eq 'fixture-user') 'User was not read by named data field.'
    Assert-Guard ($event.Domain -eq 'TEST') 'Domain was not read by named data field.'
    Assert-Guard ($event.IpAddress -eq '2001:db8::12') 'IPv6 evidence was modified or lost.'
    Assert-Guard ($event.TimeUtc -eq '2026-10-08T08:00:00.0000000Z') 'UTC event time was modified or lost.'
    $mapped = ConvertTo-GuardEventRecord -EventXml ($eventXml.Replace('2001:db8::12', '::ffff:198.51.100.12'))
    Assert-Guard ($mapped.IpAddress -eq '198.51.100.12') 'IPv4-mapped IPv6 sources were not normalized for consistent grouping.'
}

Test-GuardCase 'XML entity declarations are prohibited' {
    $eventXml = '<!DOCTYPE Event [<!ENTITY injected "test">]><Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-10-08T08:00:00Z"/></System><EventData><Data Name="TargetUserName">&injected;</Data></EventData></Event>'
    Assert-GuardThrows { ConvertTo-GuardEventRecord -EventXml $eventXml } 'Event parser allowed a DTD and entity expansion.'
}

Test-GuardCase 'Unapproved repair IDs are rejected' {
    Assert-GuardThrows { Invoke-GuardAction -ActionId 'DisableAllFirewalls' -ReceiptDirectory ([IO.Path]::GetTempPath()) -WhatIf } 'An unapproved destructive action ID was accepted.'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('Aman-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryRoot)
try {
    Test-GuardCase 'Firewall action persists previous settings before its first mutation' {
        $script:ActionTestReceiptDirectory = Join-Path $temporaryRoot 'action-receipt-before-mutation'
        Invoke-GuardIsolatedModuleTest -Configure {
            param($context)
            $script:TestReceiptDirectory = $context.ReceiptDirectory
            function script:Get-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore)
                if ($PolicyStore -eq 'PersistentStore') {
                    return @(
                        [pscustomobject]@{ Name = 'Domain'; Enabled = 'False' }
                        [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }
                        [pscustomobject]@{ Name = 'Public'; Enabled = 'False' }
                    )
                }
                return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = 'True' } })
            }
            function script:Set-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore, $Profile, $Enabled)
                $files = @(Get-ChildItem -LiteralPath $script:TestReceiptDirectory -Filter 'change-*.json' -File)
                if ($files.Count -ne 1) { throw 'Previous settings were not persisted before the fake mutation.' }
                $receipt = Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
                $script:TestSawPreparedReceipt = ($receipt.State -eq 'Prepared' -and $receipt.ActionId -eq 'EnableFirewall' -and @($receipt.Before).Count -eq 3)
                $script:TestMutationCount++
            }
        } -Context ([pscustomobject]@{ ReceiptDirectory = $script:ActionTestReceiptDirectory }) -Operation {
            param($module)
            $result = Invoke-GuardAction -ActionId 'EnableFirewall' -ReceiptDirectory $script:ActionTestReceiptDirectory -Confirm:$false
            $state = & $module { [pscustomobject]@{ Mutations = $script:TestMutationCount; SawPrepared = $script:TestSawPreparedReceipt } }
            Assert-Guard $result.Success 'A fully stubbed successful firewall action failed.'
            Assert-Guard ($state.Mutations -eq 1 -and $state.SawPrepared) 'Firewall mutation occurred without a Prepared receipt.'
            $receipt = Get-Content -LiteralPath $result.ReceiptPath -Raw | ConvertFrom-Json
            Assert-Guard ($receipt.State -eq 'Applied') 'Successful fake mutation was not recorded as Applied.'
            Assert-Guard (@($receipt.Before | Where-Object { $_.Name -eq 'Domain' -and $_.Enabled -eq 'False' }).Count -eq 1) 'Receipt did not preserve the pre-action firewall value.'
        }
    }

    Test-GuardCase 'Receipt save failure prevents every firewall mutation' {
        $script:ActionTestReceiptDirectory = Join-Path $temporaryRoot 'action-receipt-write-failure'
        Invoke-GuardIsolatedModuleTest -Configure {
            function script:Get-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore)
                return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = 'False' } })
            }
            function script:Write-GuardReceipt { param($Receipt, [string]$Path) throw 'Simulated receipt write failure.' }
            function script:Set-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore, $Profile, $Enabled)
                $script:TestMutationCount++
            }
        } -Operation {
            param($module)
            $result = Invoke-GuardAction -ActionId 'EnableFirewall' -ReceiptDirectory $script:ActionTestReceiptDirectory -Confirm:$false
            $mutations = & $module { $script:TestMutationCount }
            Assert-Guard (-not $result.Success) 'Receipt save failure was reported as a successful action.'
            Assert-Guard ($mutations -eq 0) 'A firewall mutation occurred after receipt persistence failed.'
            Assert-Guard (-not (Test-Path -LiteralPath $result.ReceiptPath)) 'The failed simulated receipt was unexpectedly present.'
        }
    }

    Test-GuardCase 'An effective firewall policy override cannot report successful hardening' {
        $script:ActionTestReceiptDirectory = Join-Path $temporaryRoot 'action-policy-override'
        Invoke-GuardIsolatedModuleTest -Configure {
            function script:Get-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore)
                return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = 'False' } })
            }
            function script:Set-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore, $Profile, $Enabled)
                $script:TestMutationCount++
            }
        } -Operation {
            param($module)
            $result = Invoke-GuardAction -ActionId 'EnableFirewall' -ReceiptDirectory $script:ActionTestReceiptDirectory -Confirm:$false
            $mutations = & $module { $script:TestMutationCount }
            Assert-Guard ($mutations -eq 1) 'The fake local firewall command was not attempted.'
            Assert-Guard (-not $result.Success) 'Ineffective firewall change was reported as successful protection.'
            $receipt = Get-Content -LiteralPath $result.ReceiptPath -Raw | ConvertFrom-Json
            Assert-Guard ($receipt.State -eq 'Failed') 'Effective-policy failure was not recorded for recovery.'
        }
    }

    Test-GuardCase 'Defender repair refuses passive or inactive protection before changing a preference' {
        $script:ActionTestReceiptDirectory = Join-Path $temporaryRoot 'action-inactive-defender'
        foreach ($status in @(
            [pscustomobject]@{ AMRunningMode = 'Passive Mode'; AMServiceEnabled = $true; AntivirusEnabled = $true }
            [pscustomobject]@{ AMRunningMode = 'Normal'; AMServiceEnabled = $false; AntivirusEnabled = $true }
            [pscustomobject]@{ AMRunningMode = 'Normal'; AMServiceEnabled = $true; AntivirusEnabled = $false }
        )) {
            $script:ActionTestDefenderStatus = $status
            Invoke-GuardIsolatedModuleTest -Configure {
                param($context)
                $script:TestDefenderStatus = $context.Status
                function script:Get-MpComputerStatus {
                    [CmdletBinding()] param()
                    return $script:TestDefenderStatus
                }
                function script:Get-MpPreference { throw 'Inactive Defender must not read mutable preferences.' }
                function script:Set-MpPreference {
                    [CmdletBinding()] param($DisableRealtimeMonitoring)
                    $script:TestMutationCount++
                }
            } -Context ([pscustomobject]@{ Status = $status }) -Operation {
                param($module)
                $result = Invoke-GuardAction -ActionId 'EnableRealtime' -ReceiptDirectory $script:ActionTestReceiptDirectory -Confirm:$false
                $mutations = & $module { $script:TestMutationCount }
                Assert-Guard (-not $result.Success) 'Inactive Defender mode was accepted for automatic repair.'
                Assert-Guard ($mutations -eq 0 -and $null -eq $result.ReceiptPath) 'Inactive Defender action reached a mutation or persisted a misleading change receipt.'
            }
        }
    }

    Test-GuardCase 'A partially applied firewall action can restore unchanged and enabled profiles' {
        $script:RestoreTestReceiptPath = Join-Path $temporaryRoot 'partial-firewall.json'
        $receipt = [pscustomobject]@{
            SchemaVersion = 1; Computer = $env:COMPUTERNAME; ActionId = 'EnableFirewall'; State = 'Failed'
            Before = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'False' }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'False' }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'True' }
            )
        }
        [IO.File]::WriteAllText($script:RestoreTestReceiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
        Invoke-GuardIsolatedModuleTest -Context ([pscustomobject]@{ CurrentProfiles = @{ Domain = 'True'; Private = 'False'; Public = 'True' } }) -Configure {
            param($context)
            $script:TestCurrentProfiles = $context.CurrentProfiles
            function script:Get-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore)
                return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = $script:TestCurrentProfiles[$_] } })
            }
            function script:Set-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore, $Profile, $Enabled)
                $script:TestMutationCount++
                $script:TestCurrentProfiles[[string]$Profile] = [string]$Enabled
            }
        } -Operation {
            param($module)
            Restore-GuardAction -ReceiptPath $script:RestoreTestReceiptPath -Confirm:$false | Out-Null
            $state = & $module { [pscustomobject]@{ Mutations = $script:TestMutationCount; Domain = $script:TestCurrentProfiles.Domain; Private = $script:TestCurrentProfiles.Private; Public = $script:TestCurrentProfiles.Public } }
            Assert-Guard ($state.Mutations -ge 1) 'No fake restoration occurred for the partially changed profile.'
            Assert-Guard ($state.Domain -eq 'False' -and $state.Private -eq 'False' -and $state.Public -eq 'True') 'Partial action restoration did not preserve every original local value.'
        }
    }

    Test-GuardCase 'Firewall restore refuses unrelated drift before any mutation' {
        $script:RestoreTestReceiptPath = Join-Path $temporaryRoot 'drifted-firewall.json'
        $receipt = [pscustomobject]@{
            SchemaVersion = 1; Computer = $env:COMPUTERNAME; ActionId = 'EnableFirewall'; State = 'Applied'
            Before = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'False' }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'False' }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'True' }
            )
        }
        [IO.File]::WriteAllText($script:RestoreTestReceiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
        Invoke-GuardIsolatedModuleTest -Context ([pscustomobject]@{ CurrentProfiles = @{ Domain = 'True'; Private = 'False'; Public = 'False' } }) -Configure {
            param($context)
            $script:TestCurrentProfiles = $context.CurrentProfiles
            function script:Get-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore)
                return @('Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = $script:TestCurrentProfiles[$_] } })
            }
            function script:Set-NetFirewallProfile {
                [CmdletBinding()] param($PolicyStore, $Profile, $Enabled)
                $script:TestMutationCount++
            }
        } -Operation {
            param($module)
            Assert-GuardThrows { Restore-GuardAction -ReceiptPath $script:RestoreTestReceiptPath -Confirm:$false } 'An unrelated firewall change was overwritten by restoration.'
            $mutations = & $module { $script:TestMutationCount }
            Assert-Guard ($mutations -eq 0) 'A partial firewall restore started before detecting unrelated drift.'
        }
    }

    Test-GuardCase 'WhatIf repairs write no receipts and report no change' {
        $receipts = Join-Path $temporaryRoot 'receipts'
        foreach ($id in @('EnableFirewall', 'EnableRealtime', 'RequireRdpNla')) {
            $result = Invoke-GuardAction -ActionId $id -ReceiptDirectory $receipts -WhatIf
            Assert-Guard (-not $result.Success) ('WhatIf reported a completed mutation: ' + $id)
            Assert-Guard ($null -eq $result.ReceiptPath) ('WhatIf created a change receipt: ' + $id)
        }
        Assert-Guard (-not (Test-Path -LiteralPath $receipts)) 'WhatIf unexpectedly created the receipt directory.'
    }

    Test-GuardCase 'Restore rejects unapproved actions and another device before WhatIf' {
        $receiptPath = Join-Path $temporaryRoot 'invalid-receipt.json'
        $receipt = [pscustomobject]@{ SchemaVersion = 1; Computer = $env:COMPUTERNAME; ActionId = 'DisableAllFirewalls'; Before = $null }
        [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
        Assert-GuardThrows { Restore-GuardAction -ReceiptPath $receiptPath -WhatIf } 'Restore accepted an unapproved action ID.'
        $receipt.ActionId = 'EnableRealtime'
        $receipt.Before = [pscustomobject]@{ DisableRealtimeMonitoring = $false }
        $receipt.Computer = '__different_device__'
        [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
        Assert-GuardThrows { Restore-GuardAction -ReceiptPath $receiptPath -WhatIf } 'Restore accepted a receipt from another device.'
    }

    Test-GuardCase 'Restore validates typed bounded previous settings before WhatIf' {
        $receiptPath = Join-Path $temporaryRoot 'invalid-values.json'
        $invalid = @(
            [pscustomobject]@{ ActionId = 'EnableRealtime'; Before = [pscustomobject]@{ DisableRealtimeMonitoring = 'false' } }
            [pscustomobject]@{ ActionId = 'RequireRdpNla'; Before = [pscustomobject]@{ UserAuthenticationRequired = 2 } }
            [pscustomobject]@{ ActionId = 'RequireRdpNla'; Before = [pscustomobject]@{ UserAuthenticationRequired = '0' } }
            [pscustomobject]@{ ActionId = 'EnableFirewall'; Before = @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }) }
            [pscustomobject]@{ ActionId = 'EnableFirewall'; Before = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'Invoke-Expression test' }
            ) }
            [pscustomobject]@{ ActionId = 'EnableFirewall'; Before = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'NotConfigured' }
            ) }
        )
        foreach ($case in $invalid) {
            $receipt = [pscustomobject]@{ SchemaVersion = 1; Computer = $env:COMPUTERNAME; ActionId = $case.ActionId; Before = $case.Before }
            [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 8), [Text.Encoding]::UTF8)
            Assert-GuardThrows { Restore-GuardAction -ReceiptPath $receiptPath -WhatIf } ('Restore accepted malformed previous settings for ' + $case.ActionId)
        }
    }

    Test-GuardCase 'Valid restoration WhatIf remains inert on every approved action' {
        $receiptPath = Join-Path $temporaryRoot 'valid-values.json'
        $valid = @(
            [pscustomobject]@{ ActionId = 'EnableRealtime'; Before = [pscustomobject]@{ DisableRealtimeMonitoring = $false } }
            [pscustomobject]@{ ActionId = 'RequireRdpNla'; Before = [pscustomobject]@{ UserAuthenticationRequired = 0 } }
            [pscustomobject]@{ ActionId = 'EnableFirewall'; Before = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'False' }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'False' }
            ) }
        )
        foreach ($case in $valid) {
            $receipt = [pscustomobject]@{ SchemaVersion = 1; Computer = $env:COMPUTERNAME; ActionId = $case.ActionId; Before = $case.Before }
            $json = $receipt | ConvertTo-Json -Depth 8
            [IO.File]::WriteAllText($receiptPath, $json, [Text.Encoding]::UTF8)
            Restore-GuardAction -ReceiptPath $receiptPath -WhatIf | Out-Null
            Assert-Guard ([IO.File]::ReadAllText($receiptPath, [Text.Encoding]::UTF8) -eq $json) ('Restore WhatIf changed the original receipt for ' + $case.ActionId)
        }
    }

    Test-GuardCase 'HTML escapes evidence and metadata, JSON preserves Unicode' {
        $payload = '<script>alert("test")</script><img src=x onerror=alert(1)>'
        $arabic = -join @([char]0x0623, [char]0x0645, [char]0x0627, [char]0x0646)
        $report = [pscustomobject]@{
            TimestampUtc = '2026-10-08T08:00:00Z'; Computer = $payload; OS = $arabic; ToolVersion = 'test'; IsAdmin = $false
            Findings = @([pscustomobject]@{ Id = $payload; Severity = 'x" onmouseover="alert(1)'; Title = $arabic + $payload; Detail = $payload; ActionId = 'EnableFirewall' })
            Sections = @{ $payload = [pscustomobject]@{ Available = $false; Error = $payload; Data = [pscustomobject]@{ Label = $arabic; Evidence = $payload } } }
        }
        $result = Export-GuardReport -Report $report -Directory (Join-Path $temporaryRoot 'reports')
        Assert-Guard (Test-Path -LiteralPath $result.JsonPath -PathType Leaf) 'JSON artifact was not written.'
        Assert-Guard (Test-Path -LiteralPath $result.HtmlPath -PathType Leaf) 'HTML artifact was not written.'
        $html = [IO.File]::ReadAllText($result.HtmlPath, [Text.Encoding]::UTF8)
        Assert-Guard ($html -notmatch '(?i)<script\b|<img\b') 'Untrusted evidence reached HTML as executable markup.'
        Assert-Guard ($html.Contains('&lt;script&gt;')) 'The metadata test payload was lost instead of displayed as encoded text.'
        Assert-Guard ($html -notmatch 'class="severity x') 'Untrusted severity entered an HTML attribute.'
        Assert-Guard ($html.Contains('Content-Security-Policy')) 'The offline report lacks its script-blocking content policy.'
        $roundTrip = [IO.File]::ReadAllText($result.JsonPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        Assert-Guard ($roundTrip.OS -eq $arabic) 'Arabic text was not preserved by JSON serialization.'
        Assert-Guard ($roundTrip.Computer -eq $payload) 'JSON evidence was changed instead of preserved.'
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Test-GuardCase 'Device collection refuses unsupported non-Windows platform' {
        Assert-GuardThrows { Get-GuardReport } 'Device collection claimed to operate on a non-Windows platform.' '(?i)Windows'
    }
    Test-GuardCase 'Native Defender operations refuse unsupported platform' {
        Assert-GuardThrows { Invoke-GuardDefenderScan } 'Defender scanning did not explicitly refuse a non-Windows platform.' '(?i)Windows'
        Assert-GuardThrows { Update-GuardDefenderSignatures } 'Signature updating did not explicitly refuse a non-Windows platform.' '(?i)Windows'
    }
} else {
    Write-Host 'SKIP: Non-Windows refusal tests (native Defender is never invoked by this harness on Windows).'
}

Write-Host ('Results: {0} passed, {1} failed.' -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0
