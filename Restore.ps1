#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$ReceiptPath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Guard.Core.psm1') -Force
if ($PSCmdlet.ShouldProcess($ReceiptPath,'استعادة الإعداد السابق؛ قد تقل حماية الجهاز')) {
    Restore-GuardAction -ReceiptPath $ReceiptPath -Confirm:$false
}
