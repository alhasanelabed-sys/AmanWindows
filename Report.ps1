#requires -Version 5.1
Set-StrictMode -Version 2.0

function ConvertTo-GuardHtml {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-GuardSectionEntries {
    param([AllowNull()][object]$Sections)
    if ($null -eq $Sections) { return @() }
    if ($Sections -is [System.Collections.IDictionary]) {
        foreach ($key in $Sections.Keys) {
            [pscustomobject]@{ Name = [string]$key; Section = $Sections[$key] }
        }
    } else {
        foreach ($property in $Sections.PSObject.Properties) {
            [pscustomobject]@{ Name = $property.Name; Section = $property.Value }
        }
    }
}

function Export-GuardReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][string]$Directory
    )
    $fullDirectory = [System.IO.Path]::GetFullPath($Directory)
    [void][System.IO.Directory]::CreateDirectory($fullDirectory)
    $fileStem = 'Aman-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $jsonPath = Join-Path $fullDirectory ($fileStem + '.json')
    $htmlPath = Join-Path $fullDirectory ($fileStem + '.html')
    $encoding = New-Object System.Text.UTF8Encoding($true)
    $json = ConvertTo-Json -InputObject $Report -Depth 40
    [System.IO.File]::WriteAllText($jsonPath, $json, $encoding)

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append(@'
<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>أمان Windows — تقرير محلي</title>
<style>
body{font-family:Segoe UI,Tahoma,Arial,sans-serif;background:#f3f5f8;color:#17243a;line-height:1.65;margin:0;padding:24px}
main{max-width:1160px;margin:auto}h1,h2,h3{line-height:1.4}header,.card{background:white;border:1px solid #d5ddeb;border-radius:10px;padding:20px;margin:0 0 18px}
.notice{background:#fff4db;border-right:5px solid #a36900;padding:14px;margin-top:16px}.muted{color:#4d5f78}.meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px}
.meta dt{font-weight:600}.meta dd{margin:0;overflow-wrap:anywhere}.counts{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}.count{border:1px solid #d5ddeb;background:#f4f6fa;padding:7px 12px;border-radius:6px}
table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:10px;text-align:right;vertical-align:top;border-bottom:1px solid #d5ddeb;overflow-wrap:anywhere}th{background:#f3f5f8}
.severity{font-weight:600}.high{color:#9b1c24}.medium{color:#855600}.info{color:#244b79}.unknown{color:#52556a}pre{background:#eef2f7;border:1px solid #d5ddeb;border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;padding:14px;font-family:Consolas,monospace;font-size:13px;unicode-bidi:plaintext;text-align:left}
.error{color:#9b1c24;white-space:pre-wrap}.details{white-space:pre-wrap}a{color:#174ea6}ul{padding-right:24px}@media(max-width:650px){body{padding:10px}header,.card{padding:14px}.meta{display:block}.meta dt{margin-top:8px}table{table-layout:auto}th,td{padding:7px}}
@media print{body{background:white;padding:0}header,.card{break-inside:avoid;border-radius:0}pre{font-size:10px}}
</style></head><body><main><header><h1>أمان Windows</h1><p>تقرير حالة وإعدادات ومؤشرات أمنية محفوظ على هذا الجهاز.</p>
<div class="notice">هذا التقرير ليس ضمانًا لسلامة الجهاز. المنافذ المفتوحة وعناوين IP وسجلات تسجيل الدخول لا تثبت وقوع اختراق أو هوية شخص. بعض الفحوص قد تكون غير متاحة بسبب الصلاحيات أو إصدار Windows أو برامج الحماية الأخرى. يحتاج الاشتباه إلى تحقق مستقل.</div><dl class="meta">
'@)
    foreach ($metadata in @(
        @('وقت الفحص (UTC)', $Report.TimestampUtc),
        @('الجهاز', $Report.Computer),
        @('نظام التشغيل', $Report.OS),
        @('إصدار أمان', $Report.ToolVersion),
        @('صلاحيات المسؤول', $(if ($Report.IsAdmin) { 'نعم' } else { 'لا — قد تكون النتائج جزئية' }))
    )) {
        [void]$builder.Append('<dt>' + (ConvertTo-GuardHtml $metadata[0]) + '</dt><dd>' + (ConvertTo-GuardHtml $metadata[1]) + '</dd>')
    }
    [void]$builder.Append('</dl><div class="counts">')
    $severityLabels = @{ High = 'عالية'; Medium = 'متوسطة'; Info = 'معلومات'; Unknown = 'غير محسومة' }
    $severityClasses = @{ High = 'high'; Medium = 'medium'; Info = 'info'; Unknown = 'unknown' }
    foreach ($severity in @('High', 'Medium', 'Info', 'Unknown')) {
        $count = @($Report.Findings | Where-Object { $_.Severity -eq $severity }).Count
        [void]$builder.Append('<span class="count">' + $severityLabels[$severity] + ': ' + $count + '</span>')
    }
    [void]$builder.Append('</div></header><section class="card"><h2>نتائج تحتاج مراجعة</h2><p class="muted">درجة الأولوية تعبّر عن الإعداد أو المؤشر المرصود، ولا تثبت وجود مهاجم.</p>')
    $findings = @($Report.Findings)
    if ($findings.Count -eq 0) {
        [void]$builder.Append('<p>لم تُسجّل نتائج في الفحوص المتاحة. راجع توافر كل فحص في الأدلة أدناه.</p>')
    } else {
        [void]$builder.Append('<table><thead><tr><th style="width:12%">الأولوية</th><th style="width:27%">النتيجة</th><th>التفاصيل</th></tr></thead><tbody>')
        foreach ($finding in $findings) {
            $severity = [string]$finding.Severity
            $label = if ($severityLabels.ContainsKey($severity)) { $severityLabels[$severity] } else { $severity }
            $class = if ($severityClasses.ContainsKey($severity)) { $severityClasses[$severity] } else { 'unknown' }
            [void]$builder.Append('<tr><td class="severity ' + $class + '">' + (ConvertTo-GuardHtml $label) + '</td><td>' + (ConvertTo-GuardHtml $finding.Title) + '<br><small dir="ltr">' + (ConvertTo-GuardHtml $finding.Id) + '</small></td><td class="details">' + (ConvertTo-GuardHtml $finding.Detail) + '</td></tr>')
        }
        [void]$builder.Append('</tbody></table>')
    }
    [void]$builder.Append('</section><section class="card"><h2>الأدلة وتوافر الفحوص</h2><p>تعرض الأقسام جميع البيانات التي أعادتها الفحوص، بما فيها الفحوص التي تعذر إكمالها. قد يحتوي التقرير على أسماء مستخدمين ومسارات وعناوين شبكة؛ احفظه في مكان خاص.</p><ul>')
    $entries = @(Get-GuardSectionEntries -Sections $Report.Sections)
    $sectionIndex = 0
    foreach ($entry in $entries) {
        [void]$builder.Append('<li><a href="#section-' + $sectionIndex + '">' + (ConvertTo-GuardHtml $entry.Name) + '</a></li>')
        $sectionIndex++
    }
    [void]$builder.Append('</ul></section>')
    $sectionIndex = 0
    foreach ($entry in $entries) {
        $section = $entry.Section
        $availability = if ($section.Available) { 'الفحص متاح' } else { 'الفحص غير متاح أو غير مكتمل' }
        [void]$builder.Append('<section class="card" id="section-' + $sectionIndex + '"><h3>' + (ConvertTo-GuardHtml $entry.Name) + '</h3><p>' + $availability + '</p>')
        if (-not [string]::IsNullOrWhiteSpace([string]$section.Error)) {
            [void]$builder.Append('<p class="error">' + (ConvertTo-GuardHtml $section.Error) + '</p>')
        }
        $evidence = ConvertTo-Json -InputObject $section.Data -Depth 40
        [void]$builder.Append('<pre dir="ltr">' + (ConvertTo-GuardHtml $evidence) + '</pre></section>')
        $sectionIndex++
    }
    [void]$builder.Append('<footer class="muted"><p>أمان Windows — فحص محلي. فحص البرمجيات الخبيثة تتولاه أدوات Windows Defender الأصلية. يجب تحديث Windows والتطبيقات ومعالجة النتائج المؤكدة؛ لا يحدد هذا البرنامج الهوية الشخصية لصاحب عنوان IP.</p></footer></main></body></html>')
    [System.IO.File]::WriteAllText($htmlPath, $builder.ToString(), $encoding)
    return [pscustomobject]@{ JsonPath = $jsonPath; HtmlPath = $htmlPath }
}
