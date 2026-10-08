#requires -Version 5.1
Set-StrictMode -Version 2.0

function Test-GuardWindows { return ($env:OS -eq 'Windows_NT') }
function Test-GuardAdmin {
    if (-not (Test-GuardWindows)) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-GuardAdmin {
    if (-not (Test-GuardWindows)) { throw 'هذه الوظيفة تتطلب Windows 10 أو 11.' }
    if (-not (Test-GuardAdmin)) { throw 'يتطلب هذا الإجراء التشغيل كمسؤول عبر UAC.' }
}
function Read-GuardSection {
    param([scriptblock]$Reader)
    try { return [pscustomobject]@{ Available=$true; Error=$null; Data=(& $Reader) } }
    catch { return [pscustomobject]@{ Available=$false; Error=$_.Exception.Message; Data=$null } }
}
function ConvertTo-GuardEventRecord {
    param([Parameter(Mandatory)][string]$EventXml)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($EventXml), $settings)
    try { $doc=[System.Xml.XmlDocument]::new(); $doc.XmlResolver=$null; $doc.Load($reader) }
    finally { $reader.Dispose() }
    $fields=@{}
    foreach ($node in $doc.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")) {
        $fields[$node.GetAttribute('Name')]=$node.InnerText
    }
    $idNode=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='EventID']")
    $timeNode=$doc.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']/*[local-name()='TimeCreated']")
    $type=0; [void][int]::TryParse([string]$fields['LogonType'],[ref]$type)
    $ip=[string]$fields['IpAddress']; $parsed=$null
    if ([System.Net.IPAddress]::TryParse($ip,[ref]$parsed) -and $parsed.IsIPv4MappedToIPv6) { $ip=$parsed.MapToIPv4().ToString() }
    return [pscustomobject]@{
        EventId=[int]$idNode.InnerText; TimeUtc=$timeNode.GetAttribute('SystemTime');
        LogonType=$type; User=[string]$fields['TargetUserName']; Domain=[string]$fields['TargetDomainName'];
        IpAddress=$ip; Status=[string]$fields['Status']; SubStatus=[string]$fields['SubStatus']
    }
}
function New-GuardFinding {
    param($Id,$Severity,$Title,$Detail,$ActionId=$null)
    [pscustomobject]@{ Id=$Id; Severity=$Severity; Title=$Title; Detail=$Detail; ActionId=$ActionId }
}
function Test-GuardFields {
    param($Object,[string[]]$Names)
    if ($null -eq $Object) { return $false }
    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) { if (-not $Object.Contains($name)) { return $false } }
        elseif ($null -eq $Object.PSObject.Properties[$name]) { return $false }
    }
    return $true
}
function Get-GuardFindings {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Sections,[bool]$IsAdmin=$false)
    $items=[System.Collections.Generic.List[object]]::new()
    $required=@('System','Defender','Detections','Firewall','RemoteAccess','SMB','UAC','Network','Startup','Logons','Updates')
    $normalized=[ordered]@{}
    foreach ($name in $required) {
        if (-not $Sections.Contains($name)) { continue }
        $s=$Sections[$name]
        if (-not (Test-GuardFields $s @('Available','Error','Data'))) {
            $normalized[$name]=[pscustomobject]@{Available=$false;Error='صيغة بيانات الفحص غير مكتملة.';Data=$null}; continue
        }
        $valid=$true
        if ($s.Available) {
            switch ($name) {
                'Defender' {
                    $valid=Test-GuardFields $s.Data @('AMRunningMode','AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','AntivirusSignatureAge')
                    if ($valid) { $valid=($null -ne $s.Data.AMRunningMode -and $s.Data.AMServiceEnabled -is [bool] -and $s.Data.AntivirusEnabled -is [bool] -and $s.Data.RealTimeProtectionEnabled -is [bool]) }
                }
                'RemoteAccess' { $valid=Test-GuardFields $s.Data @('RdpEnabled','NlaRequired'); if ($valid) { $valid=($s.Data.RdpEnabled -is [bool]) } }
                'SMB' { $valid=Test-GuardFields $s.Data @('FeatureState'); if ($valid) { $valid=($null -ne $s.Data.FeatureState) } }
                'UAC' { $valid=Test-GuardFields $s.Data @('Enabled'); if ($valid) { $valid=($s.Data.Enabled -is [bool]) } }
                'Network' { $valid=Test-GuardFields $s.Data @('Tcp','Udp') }
                'Logons' { $valid=Test-GuardFields $s.Data @('Events','Truncated','LookbackHours','Limit') }
                'Firewall' {
                    foreach ($p in @($s.Data)) { if (-not (Test-GuardFields $p @('Name','Enabled')) -or [string]$p.Enabled -notin @('True','False')) { $valid=$false; break } }
                }
                'Detections' { foreach ($t in @($s.Data)) { if ($null -ne $t -and -not (Test-GuardFields $t @('ThreatName','IsActive'))) { $valid=$false; break } } }
            }
        }
        if ($valid) { $normalized[$name]=$s }
        else { $normalized[$name]=[pscustomobject]@{Available=$false;Error='لم تتوفر جميع الحقول اللازمة؛ لا يمكن تأكيد الحالة.';Data=$null} }
    }
    $Sections=$normalized
    foreach ($name in $required) {
        if (-not $Sections.Contains($name) -or -not $Sections[$name].Available) {
            $reason='لم تتوفر بيانات الفحص.'
            if ($Sections.Contains($name) -and $Sections[$name].Error) { $reason=[string]$Sections[$name].Error }
            $items.Add((New-GuardFinding "unavailable-$name" 'Unknown' "فحص غير مكتمل: $name" $reason))
        }
    }
    if (-not $IsAdmin) { $items.Add((New-GuardFinding 'limited-permissions' 'Info' 'الفحص بصلاحيات مستخدم عادي' 'قد لا تتاح سجلات الأمان وبعض الإعدادات؛ أعد الفحص كمسؤول لتوسيع البيانات.')) }
    if ($Sections.Contains('Defender') -and $Sections.Defender.Available) {
        $d=$Sections.Defender.Data
        if ($d.AMRunningMode -eq 'Normal' -and $d.AMServiceEnabled -and $d.AntivirusEnabled) {
            if (-not $d.RealTimeProtectionEnabled) {
                $items.Add((New-GuardFinding 'defender-realtime-disabled' 'High' 'حماية Defender الفورية متوقفة' 'تم رصد Defender في الوضع النشط مع توقف الحماية الفورية. قد تمنع سياسة المؤسسة أو الحماية من العبث تغيير الإعداد.' 'EnableRealtime'))
            }
            if ($null -ne $d.AntivirusSignatureAge -and [int]$d.AntivirusSignatureAge -gt 7) {
                $items.Add((New-GuardFinding 'defender-old-signatures' 'Medium' 'تعريفات Defender تحتاج مراجعة' "العمر المرصود للتعريفات: $($d.AntivirusSignatureAge) أيام. استخدم زر تحديث التعريفات."))
            }
        } else { $items.Add((New-GuardFinding 'defender-other-mode' 'Info' 'Defender ليس في الوضع النشط المعتاد' "الوضع المرصود: $($d.AMRunningMode). قد يتولى منتج حماية آخر المهمة؛ لم يتم تقييم حماية ذلك المنتج.")) }
    }
    if ($Sections.Contains('Detections') -and $Sections.Detections.Available) {
        $active=@($Sections.Detections.Data | Where-Object { $null -ne $_ -and $_.IsActive -eq $true })
        if ($active.Count -gt 0) {
            $items.Add((New-GuardFinding 'detections-active' 'High' 'Defender يبلّغ عن تهديدات نشطة' (($active | ForEach-Object { $_.ThreatName }) -join '؛ ')))
        }
    }
    if ($Sections.Contains('Firewall') -and $Sections.Firewall.Available) {
        $profiles=@($Sections.Firewall.Data)
        if ($profiles.Count -ne 3) { $items.Add((New-GuardFinding 'firewall-incomplete' 'Unknown' 'بيانات الجدار الناري غير مكتملة' 'تعذر تأكيد حالة الملفات الثلاثة.')) }
        $disabled=@($profiles | Where-Object { [string]$_.Enabled -eq 'False' })
        if ($disabled.Count -gt 0) { $items.Add((New-GuardFinding 'firewall-disabled' 'High' 'بعض ملفات الجدار الناري معطلة' (($disabled | ForEach-Object { $_.Name }) -join ', ') 'EnableFirewall')) }
    }
    if ($Sections.Contains('RemoteAccess') -and $Sections.RemoteAccess.Available) {
        $r=$Sections.RemoteAccess.Data
        if ($r.RdpEnabled) {
            $items.Add((New-GuardFinding 'rdp-enabled' 'Info' 'سطح المكتب البعيد مفعّل' 'هذا إعداد وصول بعيد، وليس دليل اختراق أو دليل تعرض للإنترنت.'))
            if ($null -eq $r.NlaRequired) { $items.Add((New-GuardFinding 'rdp-nla-unknown' 'Unknown' 'تعذر تحديد مصادقة RDP' 'لم تتوفر بيانات موفر TerminalServices.')) }
            elseif (-not $r.NlaRequired) { $items.Add((New-GuardFinding 'rdp-nla-disabled' 'Medium' 'RDP لا يشترط مصادقة مستوى الشبكة' 'تفعيل NLA يزيد حماية الدخول؛ قد يمنع العملاء القدامى من إعادة الاتصال.' 'RequireRdpNla')) }
        }
    }
    if ($Sections.Contains('SMB') -and $Sections.SMB.Available -and $Sections.SMB.Data.FeatureState -eq 'Enabled') {
        $items.Add((New-GuardFinding 'smb1-enabled' 'Medium' 'ميزة SMB1 القديمة مثبتة ومفعلة' 'راجع حاجتك إلى الأجهزة القديمة قبل تعطيلها من ميزات Windows. حالة تثبيت الميزة لا تثبت أن خادم SMB1 يعمل أو أنه مكشوف.'))
    }
    if ($Sections.Contains('UAC') -and $Sections.UAC.Available -and -not $Sections.UAC.Data.Enabled) {
        $items.Add((New-GuardFinding 'uac-disabled' 'Medium' 'إعداد UAC معطل' 'راجع إعدادات التحكم بحساب المستخدم. قد يلزم إعادة التشغيل لتطبيق تغييرات هذا الإعداد.'))
    }
    if ($Sections.Contains('Network') -and $Sections.Network.Available) {
        $items.Add((New-GuardFinding 'network-snapshot' 'Info' 'تم جمع لقطة الاتصالات والمنافذ المحلية' 'عناوين IP والاتصالات والمنافذ ليست إثبات اختراق أو هوية شخص. لا تحدد اللقطة جهة بدء الاتصال أو ما إذا كان المنفذ مكشوفًا من الإنترنت.'))
    }
    if ($Sections.Contains('Startup') -and $Sections.Startup.Available) {
        $items.Add((New-GuardFinding 'startup-partial' 'Info' 'تم جمع بعض برامج بدء التشغيل' 'هذا الجرد لا يغطي كل آليات الاستمرار مثل مهام النظام والخدمات واشتراكات WMI. لم يتم تشغيل أي أمر من الجرد.'))
    }
    if ($Sections.Contains('Logons') -and $Sections.Logons.Available) {
        $log=$Sections.Logons.Data; $events=@($log.Events)
        $items.Add((New-GuardFinding 'logon-coverage' 'Info' 'حدود قراءة سجلات الدخول' "النافذة: $($log.LookbackHours) ساعة؛ الحد: $($log.Limit) حدث؛ بلغ الحد: $($log.Truncated). غياب الأحداث لا يثبت السلامة: قد يكون التدقيق معطلاً أو السجل ممسوحًا أو مستبدلاً."))
        foreach ($group in @($events | Where-Object { $_.EventId -eq 4625 -and $_.IpAddress -and $_.IpAddress -ne '-' } | Group-Object IpAddress)) {
            if ($group.Count -ge 10) { $items.Add((New-GuardFinding "logon-failures-$($group.Name)" 'Medium' 'محاولات دخول فاشلة متكررة تحتاج مراجعة' "$($group.Count) محاولة من المصدر الظاهر $($group.Name) خلال النافذة المرصودة. قد تنتج عن أخطاء كلمات مرور أو بيانات دخول قديمة؛ لا تحدد مهاجمًا.")) }
        }
        $rdp=@($events | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -eq 10 })
        if ($rdp.Count -gt 0) { $items.Add((New-GuardFinding 'rdp-logons' 'Info' 'رُصد دخول عبر سطح المكتب البعيد' "عدد الأحداث: $($rdp.Count). راجع الحسابات والأوقات والمصادر في التقرير للتأكد من أنها متوقعة؛ نجاح الدخول لا يثبت أنه غير مصرح به.")) }
    }
    $items.Add((New-GuardFinding 'updates-scope' 'Info' 'فحص التحديثات إرشادي' 'جرد Get-HotFix لا يغطي كل التحديثات أو ثغرات التطبيقات، ولا يؤكد تثبيت أحدث التصحيحات. افتح Windows Update وحدث تطبيقاتك.'))
    return $items.ToArray()
}
function Get-GuardReport {
    if (-not (Test-GuardWindows)) { throw 'هذا البرنامج يعمل على Windows 10 أو 11؛ لا يمكن فحص جهاز Windows من هذه البيئة.' }
    $sections=[ordered]@{}
    $sections.System=Read-GuardSection {
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $reg=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        [pscustomobject]@{ Caption=$os.Caption; Version=$os.Version; Build=$os.BuildNumber; Release=$reg.DisplayVersion; UBR=$reg.UBR; Edition=$reg.EditionID }
    }
    $sections.Defender=Read-GuardSection {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,AntivirusSignatureLastUpdated,IsTamperProtected
    }
    $sections.Detections=Read-GuardSection { @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatName,IsActive,SeverityID) }
    $sections.Firewall=Read-GuardSection { @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
    $sections.RemoteAccess=Read-GuardSection {
        $reg=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        $enabled=($reg.fDenyTSConnections -eq 0); $nla=$null; $policy=$null
        if ($enabled) {
            try { $ts=Get-GuardRdpSetting; $nla=($ts.UserAuthenticationRequired -eq 1); $policy=$ts.PolicySourceUserAuthenticationRequired }
            catch { } # Preserve unknown NLA rather than claiming it is disabled.
        }
        [pscustomobject]@{ RdpEnabled=$enabled; NlaRequired=$nla; PolicySource=$policy }
    }
    $sections.SMB=Read-GuardSection {
        $feature=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        [pscustomobject]@{ FeatureState=[string]$feature.State }
    }
    $sections.UAC=Read-GuardSection {
        $r=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
        [pscustomobject]@{ Enabled=($r.EnableLUA -eq 1) }
    }
    $sections.Network=Read-GuardSection {
        $processes=@{}; $processError=$null
        try { foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) { $processes[[int]$p.ProcessId]=$p } }
        catch { $processError=$_.Exception.Message }
        $tcp=@(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $process=$processes[[int]$_.OwningProcess]; $name=$null; $path=$null
            if ($null -ne $process) { $name=$process.Name; $path=$process.ExecutablePath }
            [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; State=[string]$_.State; OwningProcess=$_.OwningProcess; ProcessName=$name; Path=$path }
        })
        $udp=@(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $process=$processes[[int]$_.OwningProcess]; $name=$null
            if ($null -ne $process) { $name=$process.Name }
            [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; OwningProcess=$_.OwningProcess; ProcessName=$name }
        })
        [pscustomobject]@{ Tcp=$tcp; Udp=$udp; ProcessReadError=$processError; Note='Process matching is best-effort; null path/name is unknown. UDP has no remote peer.' }
    }
    $sections.Startup=Read-GuardSection { @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name,Command,Location,User) }
    $sections.Logons=Read-GuardSection {
        $events=@(); $start=(Get-Date).AddHours(-24)
        try { $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=$start} -MaxEvents 2000 -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
        [pscustomobject]@{ Events=@($events | ForEach-Object { ConvertTo-GuardEventRecord -EventXml $_.ToXml() }); Truncated=($events.Count -ge 2000); LookbackHours=24; Limit=2000 }
    }
    $sections.Updates=Read-GuardSection { @(Get-HotFix -ErrorAction Stop | ForEach-Object {
        $installed=$null; if ($_.InstalledOn) { $installed=$_.InstalledOn.ToUniversalTime().ToString('o') }
        [pscustomobject]@{ HotFixID=$_.HotFixID; InstalledOnUtc=$installed }
    }) }
    $admin=Test-GuardAdmin; $osLabel='غير متاح'
    if ($sections.System.Available) { $osLabel="$($sections.System.Data.Caption) / $($sections.System.Data.Build).$($sections.System.Data.UBR)" }
    $findings=@(Get-GuardFindings -Sections $sections -IsAdmin $admin)
    foreach ($finding in $findings) {
        if ($finding.Id -like 'unavailable-*') {
            $name=$finding.Id.Substring('unavailable-'.Length)
            if ($sections.Contains($name)) { $sections[$name]=[pscustomobject]@{Available=$false;Error=$finding.Detail;Data=$sections[$name].Data} }
        }
    }
    [pscustomobject]@{ ToolVersion='1.0.0'; TimestampUtc=[DateTime]::UtcNow.ToString('o'); Computer=$env:COMPUTERNAME; OS=$osLabel; IsAdmin=$admin; Findings=$findings; Sections=$sections }
}
function Get-GuardRdpSetting {
    $items=@(Get-CimInstance -Namespace 'root/cimv2/TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop)
    if ($items.Count -ne 1) { throw 'تعذر تحديد إعداد RDP-Tcp بصورة موثوقة.' }
    return $items[0]
}
function Get-GuardActions {
    @(
        [pscustomobject]@{ Id='EnableFirewall'; Title='تفعيل الجدار الناري'; Description='تفعيل الملفات المحلية Domain وPrivate وPublic فقط، دون تغيير قواعد الجدار. قد يتأثر الوصول الوارد؛ قد تتجاوز سياسة المؤسسة الإعداد المحلي. سيُحفظ الإعداد السابق.' },
        [pscustomobject]@{ Id='EnableRealtime'; Title='تفعيل حماية Defender الفورية'; Description='متاح فقط إذا كان Defender في الوضع النشط Normal. لا يغير الاستثناءات أو الحماية من العبث أو إعدادات إرسال العينات. سيُحفظ الإعداد السابق.' },
        [pscustomobject]@{ Id='RequireRdpNla'; Title='اشتراط مصادقة NLA لـ RDP'; Description='يشترط المصادقة قبل إنشاء جلسة RDP. قد يمنع العملاء القدامى من إعادة الاتصال. لا يفعّل RDP ولا يعيد تشغيل خدماته؛ لا يتجاوز سياسة المؤسسة. سيُحفظ الإعداد السابق.' }
    )
}
function Write-GuardReceipt {
    param($Receipt,[string]$Path)
    $text=$Receipt | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($Path,$text,[System.Text.UTF8Encoding]::new($true))
}
function Invoke-GuardAction {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)][ValidateSet('EnableFirewall','EnableRealtime','RequireRdpNla')][string]$ActionId,
          [Parameter(Mandatory)][string]$ReceiptDirectory)
    if (-not $PSCmdlet.ShouldProcess($ActionId,'تغيير إعداد الحماية المحلي')) { return [pscustomobject]@{ Success=$false; Message='لم يطبق أي تغيير.'; ReceiptPath=$null } }
    $path=$null; $receipt=$null
    try {
        Assert-GuardAdmin
        $before=$null
        switch ($ActionId) {
            'EnableFirewall' {
                $profiles=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
                if ($profiles.Count -ne 3) { throw 'تعذر قراءة ملفات الجدار الثلاثة.' }
                $before=@($profiles | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled } })
                if ((@($before.Name | Sort-Object -Unique) -join ',') -ne 'Domain,Private,Public') { throw 'أسماء ملفات الجدار غير متوقعة؛ لم يطبق أي تغيير.' }
                foreach ($p in $before) { if ($p.Enabled -notin @('True','False')) { throw 'تعذر حفظ حالة محلية قابلة للاستعادة؛ لم يطبق أي تغيير.' } }
            }
            'EnableRealtime' {
                $status=Get-MpComputerStatus -ErrorAction Stop
                if ($status.AMRunningMode -ne 'Normal' -or -not $status.AMServiceEnabled -or -not $status.AntivirusEnabled) { throw 'Defender ليس في الوضع النشط؛ راجع منتج الحماية الحالي.' }
                $pref=Get-MpPreference -ErrorAction Stop
                $before=[pscustomobject]@{ DisableRealtimeMonitoring=[bool]$pref.DisableRealtimeMonitoring }
            }
            'RequireRdpNla' {
                $rdp=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
                if ($rdp.fDenyTSConnections -ne 0) { throw 'RDP معطل؛ لا حاجة لهذا الإجراء.' }
                $ts=Get-GuardRdpSetting
                if ($ts.PolicySourceUserAuthenticationRequired -eq 1) { throw 'NLA يديره نهج المؤسسة؛ لن يتجاوزه البرنامج.' }
                $before=[pscustomobject]@{ UserAuthenticationRequired=[int]$ts.UserAuthenticationRequired }
            }
        }
        $dir=[System.IO.Directory]::CreateDirectory($ReceiptDirectory).FullName
        $path=Join-Path $dir ("change-{0}-{1}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'),[Guid]::NewGuid().ToString('N'))
        $receipt=[pscustomobject]@{ SchemaVersion=1; Computer=$env:COMPUTERNAME; ActionId=$ActionId; TimestampUtc=[DateTime]::UtcNow.ToString('o'); State='Prepared'; Before=$before; Message=$null }
        Write-GuardReceipt -Receipt $receipt -Path $path # Persist BEFORE the first system mutation.
        switch ($ActionId) {
            'EnableFirewall' {
                Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
                $effective=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
                if ($effective.Count -ne 3 -or @($effective | Where-Object { [string]$_.Enabled -ne 'True' }).Count -gt 0) { throw 'لم يتأكد التفعيل الفعلي؛ قد تتجاوزه سياسة المؤسسة. راجع ملف التغيير.' }
            }
            'EnableRealtime' {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                if (-not (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled) { throw 'لم يتأكد تفعيل الحماية؛ راجع سياسة المؤسسة والحماية من العبث.' }
            }
            'RequireRdpNla' {
                $result=Invoke-CimMethod -InputObject $ts -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=[uint32]1} -ErrorAction Stop
                if ($result.ReturnValue -ne 0 -or (Get-GuardRdpSetting).UserAuthenticationRequired -ne 1) { throw 'لم يتأكد تفعيل NLA.' }
            }
        }
        $receipt.State='Applied'; $receipt.Message='تم تطبيق الإعداد والتحقق من حالته.'
        Write-GuardReceipt -Receipt $receipt -Path $path
        return [pscustomobject]@{ Success=$true; Message=$receipt.Message; ReceiptPath=$path }
    } catch {
        $message=$_.Exception.Message
        if ($null -ne $receipt) { $receipt.State='Failed'; $receipt.Message=$message; try { Write-GuardReceipt -Receipt $receipt -Path $path } catch { $message += ' تعذر تحديث ملف التغيير.' } }
        return [pscustomobject]@{ Success=$false; Message=$message; ReceiptPath=$path }
    }
}
function Restore-GuardAction {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)][string]$ReceiptPath)
    $r=Get-Content -LiteralPath $ReceiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($r.SchemaVersion -ne 1 -or $r.Computer -ne $env:COMPUTERNAME -or $r.ActionId -notin @('EnableFirewall','EnableRealtime','RequireRdpNla')) { throw 'ملف الاستعادة لا يطابق الصيغة أو الجهاز أو قائمة الإجراءات المسموحة.' }
    # Validate all data before any mutation. Receipts never contain executable commands.
    switch ($r.ActionId) {
        'EnableFirewall' {
            $profiles=@($r.Before)
            if ($profiles.Count -ne 3 -or (@($profiles.Name | Sort-Object -Unique) -join ',') -ne 'Domain,Private,Public') { throw 'ملفات الجدار في النسخة السابقة غير صالحة.' }
            foreach ($p in $profiles) { if ($p.Enabled -notin @('True','False')) { throw 'قيمة جدار محلية غير صالحة.' } }
        }
        'EnableRealtime' { if ($r.Before.DisableRealtimeMonitoring -isnot [bool]) { throw 'قيمة Defender غير صالحة.' } }
        'RequireRdpNla' { if ($r.Before.UserAuthenticationRequired -isnot [long] -and $r.Before.UserAuthenticationRequired -isnot [int]) { throw 'قيمة NLA غير صالحة.' }; if ($r.Before.UserAuthenticationRequired -notin @(0,1)) { throw 'قيمة NLA غير صالحة.' } }
    }
    if (-not $PSCmdlet.ShouldProcess($r.ActionId,'استعادة الإعداد السابق؛ قد تقل الحماية')) { return }
    Assert-GuardAdmin
    switch ($r.ActionId) {
        'EnableFirewall' {
            $current=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
            if ($current.Count -ne 3) { throw 'تعذر قراءة جميع الإعدادات الحالية؛ أوقفت الاستعادة.' }
            foreach ($p in $profiles) {
                $matches=@($current | Where-Object { $_.Name -eq $p.Name })
                if ($matches.Count -ne 1 -or [string]$matches[0].Enabled -notin @('True',$p.Enabled)) { throw 'تغيرت الإعدادات منذ الإجراء؛ أوقفت الاستعادة لتجنب الكتابة فوق تغيير آخر.' }
            }
            foreach ($p in $profiles) {
                if ([string](@($current | Where-Object { $_.Name -eq $p.Name })[0].Enabled) -ne $p.Enabled) { Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $p.Name -Enabled $p.Enabled -ErrorAction Stop }
            }
            $restored=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
            foreach ($p in $profiles) { if (@($restored | Where-Object { $_.Name -eq $p.Name -and [string]$_.Enabled -eq $p.Enabled }).Count -ne 1) { throw 'تعذر تأكيد الاستعادة؛ راجع الجدار الناري.' } }
        }
        'EnableRealtime' {
            $status=Get-MpComputerStatus -ErrorAction Stop
            if ($status.AMRunningMode -ne 'Normal' -or (Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring -ne $false) { throw 'تغير وضع Defender أو إعداده؛ أوقفت الاستعادة.' }
            Set-MpPreference -DisableRealtimeMonitoring $r.Before.DisableRealtimeMonitoring -ErrorAction Stop
            if ((Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring -ne $r.Before.DisableRealtimeMonitoring) { throw 'تعذر تأكيد استعادة تفضيل Defender.' }
        }
        'RequireRdpNla' {
            $ts=Get-GuardRdpSetting
            if ($ts.PolicySourceUserAuthenticationRequired -eq 1 -or $ts.UserAuthenticationRequired -ne 1) { throw 'تغير إعداد NLA أو أصبح مدارًا؛ أوقفت الاستعادة.' }
            $result=Invoke-CimMethod -InputObject $ts -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=[uint32]$r.Before.UserAuthenticationRequired} -ErrorAction Stop
            if ($result.ReturnValue -ne 0 -or (Get-GuardRdpSetting).UserAuthenticationRequired -ne $r.Before.UserAuthenticationRequired) { throw 'تعذر تأكيد استعادة NLA.' }
        }
    }
    'تمت استعادة الإعداد السابق. أعد الفحص.'
}
function Invoke-GuardDefenderScan {
    param([ValidateSet('QuickScan','FullScan')][string]$ScanType='QuickScan')
    Assert-GuardAdmin
    $status=Get-MpComputerStatus -ErrorAction Stop
    if ($status.AMRunningMode -ne 'Normal' -or -not $status.AntivirusEnabled) { throw 'Defender غير نشط. استخدم منتج الحماية الحالي.' }
    Start-MpScan -ScanType $ScanType -ErrorAction Stop
    'تم إرسال طلب الفحص إلى Defender. راجع سجل الحماية وحالة الفحص في Windows Security؛ طلب الفحص لا يضمن خلو الجهاز.'
}
function Update-GuardDefenderSignatures {
    Assert-GuardAdmin
    Update-MpSignature -ErrorAction Stop
    'انتهى أمر تحديث تعريفات Defender؛ أعد الفحص لمراجعة تاريخها.'
}
Export-ModuleMember -Function Get-GuardReport,Get-GuardFindings,ConvertTo-GuardEventRecord,Get-GuardActions,Invoke-GuardAction,Restore-GuardAction,Invoke-GuardDefenderScan,Update-GuardDefenderSignatures
