describe 'Test M365 output report' {
    it 'Compare reports' {
        $referenceReport = Get-Content -Path reference.json
        $latestReport = Get-content -Path (Get-ChildItem -Filter "*_report.json" $PScriptRoot | Sort LastWriteTime | Select-Object -last 1)

        $latestReport | Should Be $referenceReport
    }
}