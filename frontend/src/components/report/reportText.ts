const verdictMap: Record<string, string> = {
    clean: '未發現威脅',
    low: '低風險',
    medium: '中風險',
    high: '高風險',
    suspicious: '可疑',
    malicious: '惡意',
    unknown: '未知',
    pending: '等待中',
}

const stageMap: Record<string, string> = {
    upload: '上傳',
    'file-type': '檔案類型判定',
    clamav: '防毒掃描',
    yara: 'YARA 規則比對',
    'ioc-extract': 'IOC 擷取',
    'archive-extract': '封存解壓',
    sandbox: '沙箱分析',
    sandbox_pending: '等待沙箱結果',
    'format-analysis': '格式分析',
    deobfuscation: '去混淆',
    'document-analysis': '文件分析',
    unknown: '未知',
}

const statusMap: Record<string, string> = {
    none: '正常',
    ok: '正常',
    blocked: '受阻',
    degraded: '降級',
    pending: '等待中',
    unknown: '未知',
    complete: '完成',
    completed: '完成',
    partial: '部分完成',
    running: '執行中',
    scanning: '分析中',
    queued: '排隊中',
    deferred: '等待動態分析',
    disabled: '未啟用',
    not_requested: '未要求',
    skipped: '略過',
    unsupported: '不支援',
    not_applicable: '不適用',
    unavailable: '無法使用',
    failed: '失敗',
    error: '失敗',
    timeout: '逾時',
    password_required: '等待檔案密碼',
    synthetic: '合成測試資料',
    mock: '合成測試資料',
    no_rules: '未配置規則',
    budget_exceeded: '超出分析預算',
}

const analyzerMap: Record<string, string> = {
    script: '腳本',
    office: 'Office 文件',
    pdf: 'PDF 文件',
}

const severityMap: Record<string, string> = {
    info: '資訊',
    informational: '資訊',
    critical: '嚴重',
    high: '高',
    medium: '中',
    low: '低',
}

const confidenceMap: Record<string, string> = {
    high: '高',
    medium: '中',
    low: '低',
}

const diagnosticCategoryMap: Record<string, string> = {
    blocked: '阻斷',
    coverage_gap: '涵蓋缺口',
    degraded: '降級',
}

const effectMap: Record<string, string> = {
    possible_false_negative: '可能低估風險',
    possible_false_positive: '可能高估風險',
    context_only: '僅供脈絡參考',
}

const directionMap: Record<string, string> = {
    possible_false_negative: '可能低估風險',
    possible_false_positive: '可能高估風險',
    context_only: '脈絡性提示',
}

const diagnosticCodeMap: Record<string, string> = {
    password_attempts_exhausted: '密碼嘗試次數已耗盡',
    no_matching_analyzer: '沒有可用分析器',
    parser_error: '解析失敗',
    stage_timeout: '分析階段逾時',
    candidate_cap_reached: '候選內容上限已達',
    wall_time_reached: '分析時間上限已達',
    max_depth_reached: '分析深度已達上限',
    unsupported_format: '格式不受支援',
    extraction_failed: '解壓失敗',
    descendant_rollup_without_local_confirmation: '僅由子層風險抬升',
    no_rules: '未配置規則，未執行規則掃描',
    rules_unavailable: '規則無法使用',
    no_yara_rules: '未配置 YARA 規則',
    yara_rules_missing: '未配置 YARA 規則',
    provider_unavailable: '動態分析 Provider 無法使用',
    sandbox_disabled: '未啟用動態分析',
    synthetic_provider: '使用合成測試 Provider',
}

const uncertaintyKindMap: Record<string, string> = {
    heuristic_only_verdict: '僅由啟發式證據支撐判定',
    decoded_content_truncated: '解碼內容遭截斷',
    parser_fallback_used: '使用解析降級路徑',
    unsupported_inner_format: '內層格式不受支援',
    duplicate_descendant_skipped: '已略過重複子層檔案',
    partial_ioc_provenance: 'IOC 來源資訊不完整',
    tree_inheritance_elevated_root: '最外層判定受子層風險抬升',
}

const scoreComponentTypeMap: Record<string, string> = {
    evidence: '證據貢獻',
    descendant_inheritance: '子層風險繼承',
    descendant_risk_floor: '子檔風險下限',
    synergy_bonus: '交叉印證加分',
    dampener: '抑制因子',
}

const labelMap: Record<string, string> = {
    yara_context_observation: 'YARA 資訊觀察',
    benign_context: '資訊觀察／不計入風險',
    confirmed_malware_signature: '惡意特徵命中',
    raw_url_ioc: 'URL IOC',
    raw_domain_ioc: '網域 IOC',
    raw_ip_ioc: 'IP IOC',
    ioc_multiple_types_bonus: '多類型 IOC 交叉佐證',
    ioc_multiple_types_observation: '多類型網路指標觀察',
    'script.encoded_command_execution': '編碼指令執行行為',
    deobfuscated_payload_execution: '解碼後顯示執行型載荷',
    sandbox_confirmed_malicious_behavior: '沙箱確認惡意行為',
}

const directTextMap: Record<string, string> = {
    invalid_archive_password: '檔案密碼格式無效，請使用 1 至 256 個字元且不含空字元。',
    archive_not_waiting: '此檔案目前未等待密碼，請重新取得工作狀態。',
    password_attempt_limit: '已達密碼嘗試上限，無法再次提交密碼。',
    'Password attempts exhausted': '已達密碼嘗試上限，無法再次提交密碼。',
    wrong_password: '密碼不正確，請確認這個檔案的密碼後再試一次。',
    'Archive password was rejected': '密碼不正確，請確認這個檔案的密碼後再試一次。',
    'Archive password is required': '此檔案需要密碼才能繼續分析。',
    'Office password was rejected': '密碼不正確，請確認這個 Office 文件的密碼後再試一次。',
    'Office password is required': '此 Office 文件需要密碼才能繼續分析。',
    Explainability: '可解釋性',
    'Explainability summary is available for this report.': '此報告已產生可解釋性摘要。',
    'One nested artifact drove the final suspicious verdict.': '一個巢狀內層檔案主導了最終的可疑判定。',
    'The root artifact drove the final verdict.': '最終判定主要由最外層檔案本身產生。',
    'The root artifact is elevated by descendant inheritance.': '最外層檔案的判定是由子層檔案風險繼承所抬升。',
    'The root artifact verdict is elevated by descendant inheritance.': '最外層檔案的判定是由子層檔案風險繼承所抬升。',
    'The final verdict comes from direct evidence on the scored artifact.': '最終判定來自該檔案本身的直接證據。',
    'No grouped findings were synthesized for this report.': '這份報告目前沒有可分組呈現的重要發現。',
    'No detailed score components were recorded for this report.': '這份報告目前沒有更細部的分數構成紀錄。',
    'No timeline events were synthesized for this report.': '這份報告目前沒有可顯示的時間軸事件。',
    'No blocking or degraded diagnostics were recorded.': '目前沒有阻斷或降級類型的診斷項目。',
    'No uncertainty notes were synthesized for this report.': '目前沒有額外的不確定性說明。',
    'Artifact registered for analysis.': '已將檔案建立為分析節點。',
    'Decoded content was extracted during deobfuscation.': '在去混淆階段擷取到解碼內容。',
    'Inner archive layers were blocked by extraction failure.': '內層封存內容因解壓失敗而無法分析。',
    'No blocking coverage gaps were detected.': '未偵測到阻斷型分析缺口。',
    'No blocking coverage gaps were detected for the scored artifacts.': '在已評分的檔案路徑中，未偵測到阻斷型分析缺口。',
    'inner members were never extracted': '內層成員未被成功解壓，因此無法進一步分析。',
    'Archive extraction failed after 3 incorrect password attempts.': '連續 3 次密碼錯誤，封存檔解壓失敗。',
    'collect the correct password and resubmit': '請提供正確密碼後重新送件。',
    'Encoded payload and execution primitives appear together': '偵測到編碼後載荷與執行指令同時出現。',
    'direct malicious child artifact inherited into root report': '直接子檔案為惡意，風險已繼承到最外層報告。',
    'descendant risk inherited into root report': '子層檔案的風險已繼承到最外層報告。',
    'Observed multiple IOC types in the same artifact': '同一檔案中觀察到多種類型 IOC。',
    'Decoded content reveals execution-oriented payload': '解碼內容顯示具有執行行為導向的載荷。',
    'Sandbox confirmed malicious behavior': '沙箱確認存在惡意行為。',
}

function translateByMap(value: string | null | undefined, map: Record<string, string>): string {
    if (!value) {
        return ''
    }

    return map[value] ?? value
}

export function localizeVerdict(value: string | null | undefined): string {
    return translateByMap(value, verdictMap)
}

export function localizeStage(value: string | null | undefined): string {
    return translateByMap(value, stageMap)
}

export function localizeStatus(value: string | null | undefined): string {
    return translateByMap(value, statusMap)
}

export function localizeAnalyzer(value: string | null | undefined): string {
    return translateByMap(value, analyzerMap)
}

export function localizeSeverity(value: string | null | undefined): string {
    return translateByMap(value, severityMap)
}

export function localizeConfidence(value: string | null | undefined): string {
    return translateByMap(value, confidenceMap)
}

export function localizeDiagnosticCode(value: string | null | undefined): string {
    return translateByMap(value, diagnosticCodeMap)
}

export function localizeDiagnosticCategory(value: string | null | undefined): string {
    return translateByMap(value, diagnosticCategoryMap)
}

export function localizeEffect(value: string | null | undefined): string {
    return translateByMap(value, effectMap)
}

export function localizeDirection(value: string | null | undefined): string {
    return translateByMap(value, directionMap)
}

export function localizeUncertaintyKind(value: string | null | undefined): string {
    return translateByMap(value, uncertaintyKindMap)
}

export function localizeScoreComponentType(value: string | null | undefined): string {
    return translateByMap(value, scoreComponentTypeMap)
}

export function localizeFindingLabel(value: string | null | undefined): string {
    return translateByMap(value, labelMap)
}

export function localizeReportText(value: string | null | undefined): string {
    if (!value) {
        return ''
    }

    const trimmed = value.trim()

    if (directTextMap[trimmed]) {
        return directTextMap[trimmed]
    }

    if (labelMap[trimmed]) {
        return labelMap[trimmed]
    }

    if (diagnosticCodeMap[trimmed]) {
        return diagnosticCodeMap[trimmed]
    }

    if (verdictMap[trimmed]) {
        return verdictMap[trimmed]
    }

    const observedUrlPrefix = 'Observed URL IOC '
    if (trimmed.startsWith(observedUrlPrefix)) {
        return `偵測到 URL IOC：${trimmed.slice(observedUrlPrefix.length)}`
    }

    const observedDomainPrefix = 'Observed domain IOC '
    if (trimmed.startsWith(observedDomainPrefix)) {
        return `偵測到網域 IOC：${trimmed.slice(observedDomainPrefix.length)}`
    }

    const observedIpPrefix = 'Observed IP IOC '
    if (trimmed.startsWith(observedIpPrefix)) {
        return `偵測到 IP IOC：${trimmed.slice(observedIpPrefix.length)}`
    }

    const clamavPrefix = 'ClamAV reported malware signature '
    if (trimmed.startsWith(clamavPrefix)) {
        return `ClamAV 偵測到惡意特徵：${trimmed.slice(clamavPrefix.length)}`
    }

    const yaraMatch = trimmed.match(/^YARA classification (.+) matched rule (.+)$/)
    if (yaraMatch) {
        const classification = yaraMatch[1].toLowerCase()
        return `YARA 以 ${classification === 'informational' ? '資訊性' : localizeReportText(classification)} 分類命中規則：${yaraMatch[2]}`
    }

    const deobPrefix = 'Deobfuscation detected technique '
    if (trimmed.startsWith(deobPrefix)) {
        return `去混淆偵測到技術：${trimmed.slice(deobPrefix.length)}`
    }

    return trimmed
}
