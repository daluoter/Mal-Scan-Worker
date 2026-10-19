import type { ArtifactTreeNode, Report } from '../../api/types'

interface RiskValue {
    score?: number | null
    risk_level?: string | null
    verdict?: string | null
}

// Keep legacy score fallback aligned with shared scoring/policy.py. A
// malicious verdict still requires the supplied classification, not color.
const HIGH_RISK_MIN_SCORE = 60

export interface PresentedRisk {
    score: number | null
    level: string
    verdict: string
    sourceId?: string
    sourcePath?: string
    sourceFilename?: string
}

export interface ArtifactRiskPresentation {
    local: PresentedRisk
    localRiskKnown: boolean
    recorded: PresentedRisk
    effective: PresentedRisk
    descendant?: PresentedRisk
    legacyDescendantFallback: boolean
}

function knownScore(value: number | null | undefined): number | null {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null
}

function presentedRisk(value: RiskValue, node?: ArtifactTreeNode): PresentedRisk {
    const score = knownScore(value.score)
    let level = value.risk_level || value.verdict || 'unknown'
    if (level === 'suspicious') level = score !== null && score >= HIGH_RISK_MIN_SCORE ? 'high' : 'medium'
    // Older reports may have a score and legacy verdict but no risk level.
    if (!value.risk_level && level !== 'malicious' && score !== null && score >= HIGH_RISK_MIN_SCORE) level = 'high'
    return { score, level, verdict: value.verdict || 'unknown', sourceId: node?.id,
        sourcePath: node?.display_path || node?.origin_path || node?.filename, sourceFilename: node?.filename }
}

function severity(risk: PresentedRisk): number {
    if (risk.verdict === 'malicious' || risk.level === 'malicious') return 5
    if (risk.level === 'high') return 4
    if (risk.level === 'medium' || risk.verdict === 'suspicious') return 3
    if (risk.level === 'low') return 2
    if (risk.level === 'clean' || risk.verdict === 'clean') return 1
    return 0
}

function stronger(left: PresentedRisk, right: PresentedRisk): PresentedRisk {
    const leftSeverity = severity(left)
    const rightSeverity = severity(right)
    if (leftSeverity !== rightSeverity) return leftSeverity > rightSeverity ? left : right
    return (left.score ?? -1) >= (right.score ?? -1) ? left : right
}

export function riskIsElevated(risk: PresentedRisk): boolean {
    return severity(risk) >= 4
}

export function riskBadgeClass(risk: PresentedRisk): string {
    if (riskIsElevated(risk)) return 'border-alert-red/60 bg-alert-red/15 text-alert-red'
    if (severity(risk) === 3) return 'border-caution-yellow/40 text-caution-yellow'
    if (severity(risk) > 0) return 'border-matrix-green/30 text-matrix-green'
    return 'border-white/10 text-slate-300'
}

export function riskLabel(risk: PresentedRisk): string {
    if (risk.level === 'malicious' || risk.verdict === 'malicious') return '惡意'
    if (risk.level === 'high') return '高風險'
    if (risk.level === 'medium') return '中風險'
    if (risk.level === 'low') return '低風險'
    if (risk.level === 'clean' || risk.verdict === 'clean') return '未發現威脅'
    return '未知'
}

export function artifactReferenceIsVerified(node: ArtifactTreeNode): boolean {
    const reference = node.analysis_reference
    return !reference || (reference.status === 'verified'
        && (reference.mode === 'direct' || reference.mode === 'inherited')
        && (!reference.source_sha256 || !node.sha256 || reference.source_sha256 === node.sha256)
        && (reference.source_size == null || node.size == null || reference.source_size === node.size)
        && (reference.mode !== 'direct' || !reference.source_artifact_id || reference.source_artifact_id === node.id))
}

export function artifactRiskPresentations(tree: ArtifactTreeNode): Map<ArtifactTreeNode, ArtifactRiskPresentation> {
    const risks = new Map<ArtifactTreeNode, ArtifactRiskPresentation>()
    const visit = (node: ArtifactTreeNode): ArtifactRiskPresentation => {
        const hasLocalRisk = node.local_score != null || node.local_risk_level != null || node.local_verdict != null
        const verifiedIdentity = artifactReferenceIsVerified(node)
        const local = presentedRisk(verifiedIdentity && hasLocalRisk ? {
            score: node.local_score, risk_level: node.local_risk_level, verdict: node.local_verdict,
        } : {}, node)
        const reference = node.analysis_reference
        const recorded = presentedRisk(verifiedIdentity ? node : {}, node)
        let effective = recorded
        if (verifiedIdentity && reference?.mode === 'inherited' && reference.risk) {
            effective = stronger(effective, presentedRisk(reference.risk, node))
        }
        let descendant: PresentedRisk | undefined
        for (const child of node.children ?? []) {
            const childRisk = visit(child).effective
            descendant = descendant ? stronger(descendant, childRisk) : childRisk
        }
        // Historical ancestor scores may include discounted child risk. They
        // are not direct scores; expose the strongest visible descendant
        // without rewriting the recorded score or inventing a local snapshot.
        const supplied = effective
        if (descendant) effective = stronger(effective, descendant)
        if (hasLocalRisk && descendant && stronger(local, descendant) === descendant
            && severity(effective) === severity(descendant) && effective.score === descendant.score) {
            effective = { ...effective, sourceId: descendant.sourceId,
                sourcePath: descendant.sourcePath, sourceFilename: descendant.sourceFilename }
        }
        const result = { local, localRiskKnown: hasLocalRisk && verifiedIdentity, recorded, effective, descendant,
            legacyDescendantFallback: effective !== supplied && !hasLocalRisk }
        risks.set(node, result)
        return result
    }
    visit(tree)
    return risks
}

export function reportRiskPresentation(report: Pick<Report, 'score' | 'risk_level' | 'verdict' | 'risk' | 'artifact_tree'>): ArtifactRiskPresentation {
    const supplied = presentedRisk(report)
    const localRiskKnown = Boolean(report.risk?.local_risk && (
        report.risk.local_risk.score != null || report.risk.local_risk.risk_level != null || report.risk.local_risk.verdict != null
    ))
    const local = localRiskKnown ? presentedRisk(report.risk!.local_risk!) : presentedRisk({})
    const treeRisk = report.artifact_tree ? artifactRiskPresentations(report.artifact_tree).get(report.artifact_tree) : undefined
    const effective = treeRisk ? stronger(supplied, treeRisk.effective) : supplied
    return { local, localRiskKnown, recorded: supplied, effective, descendant: treeRisk?.descendant,
        legacyDescendantFallback: effective !== supplied && !localRiskKnown }
}
