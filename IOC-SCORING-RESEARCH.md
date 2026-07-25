# IOC Scoring Optimization Research

> Research compiled for Kerennnn SOC Toolbox
> Sources: Academic papers, MISP/OpenCTI frameworks, Reddit/GitHub community, industry platforms
> Date: 2026-07-25

---

## Executive Summary

The current Kerennnn scoring engine (`api/correlate.js`) uses a weighted-average + risk-floor approach across 5 TI sources. This is solid but has clear optimization paths identified from academic research and production TIPs (MISP, OpenCTI, TheHive/Cortex). The highest-impact improvements are: (1) time decay, (2) cross-source corroboration bonus, (3) IOC-type-specific weights, and (4) Bayesian posterior aggregation.

---

## 1. Current Kerennnn Scoring (Baseline)

### Sources & Weights

| Source        | Weight | IOC Types      | Scoring Method                     |
|---------------|--------|----------------|------------------------------------|
| VirusTotal    | 0.30   | IP, domain, hash | (malicious + suspicious) / total × 100 |
| AbuseIPDB     | 0.20   | IP only        | abuseConfidenceScore + report boost |
| Abuse.ch      | 0.20   | IP, domain     | URL count + online status          |
| AlienVault OTX| 0.15   | IP, domain, hash | Pulse count + recency + families  |
| URLScan.io    | 0.20   | domain only    | Verdict score + tags               |
| Enrichment    | 0.00   | IP, domain     | Context-only (RDAP, GeoIP)         |

### Current Formula

```
baseline = weighted_avg(verdict_score × source_weight)
floor = trust_weighted_threshold(malicious_weight, suspicious_weight)
bonus = min(sum(risk_factors.bonus), 25)
confidence = min(100, max(baseline, floor) + bonus)
```

Verdict score mapping: malicious=1.0, suspicious=0.5, unknown=0.2, clean=0.0

### Risk Factor Bonuses (capped at 25)

| Factor                  | Severity | Bonus | Source     |
|-------------------------|----------|-------|------------|
| VT ≥5 malicious engines | high     | 10    | VT         |
| VT ≥1 malicious engine  | med      | 5     | VT         |
| ≥25 abuse reports       | high     | 15    | AbuseIPDB  |
| ≥10 abuse reports       | med      | 10    | AbuseIPDB  |
| High-risk hoster ISP    | med      | 10    | AbuseIPDB  |
| Datacenter usage type   | low      | 5     | AbuseIPDB  |
| Malware family link     | high     | 10    | OTX        |
| Recent pulse (<30d)     | med      | 5     | OTX        |
| Online malicious URLs   | high     | 10    | Abuse.ch   |
| URLScan malicious       | high     | 12    | URLScan    |
| URLScan phishing tag    | high     | 12    | URLScan    |
| Newly registered <30d   | high     | 10    | Enrichment |
| Recently registered <90d| med      | 5     | Enrichment |
| High-risk ASN/org       | med      | 10    | Enrichment |

### Floor System

| Condition                                           | Floor |
|-----------------------------------------------------|-------|
| maliciousWeight ≥ 0.50 OR (ratio ≥ 0.60 AND count ≥ 2) | 70    |
| maliciousWeight ≥ 0.20 OR (ratio ≥ 0.50 AND count ≥ 1) | 40    |
| suspiciousWeight ≥ 0.50 OR (ratio ≥ 0.60 AND count ≥ 2)| 40    |
| suspiciousWeight ≥ 0.25 OR (ratio ≥ 0.40 AND count ≥ 1)| 25    |

---

## 2. Industry Frameworks & Research

### 2.1 MISP Indicator Scoring (Dulaunoy et al., 2018)

**Paper**: "An Indicator Scoring Method for MISP Platforms" (TNC18, cited 11×)

**Core formula** — polynomial decay:

```
score(t) = base_score × (1 - (t/τ)^α)
```

- `base_score` ∈ [0, 100] — combination of taxonomy weights + source confidence
- `t` = time since last sighting (hours)
- `τ` = end-time — when score reaches 0 (e.g., 7 days for IPs, 60 days for hashes)
- `α` = decay speed — higher values = faster initial decay

**Key parameters by IOC type** (from their phishing dataset analysis):

| IOC Type  | τ (end-time) | α (decay speed) | Half-life  |
|-----------|-------------|-----------------|------------|
| IP (botnet) | 7 days    | 1.81            | ~48 hours  |
| Hash (malware) | 60 days | 0.3             | ~30 days   |
| URL (phishing) | 5 days  | 1.3             | ~72 hours  |

**Taxonomy confidence scales**:

| MISP Scale          | Value | OSINT Scale        | Value |
|---------------------|-------|--------------------|-------|
| Completely confident | 100   | Certain            | 100   |
| Usually confident    | 75    | Almost certain     | 93    |
| Fairly confident     | 50    | Probable           | 75    |
| Rarely confident     | 25    | Chances about even | 50    |
| Unconfident          | 0     | Probably not       | 30    |
|                      |       | Impossibility      | 0     |

**Source confidence**: per-organization trust level [0, 1], adjustable per time window.

**Sighting**: resets score to base_score (IOCs get a "second life" when re-observed).

**Key insight for Kerennnn**: The polynomial decay model is superior to linear/exponential because it controls both the end-time AND the slope shape. Fast decay early (IPs rotate quickly), slow decay later (long-tail relevance).

### 2.2 STIX 2.1 Confidence Model

**Spec**: OASIS STIX Version 2.1 (§7.1 — Confidence)

- 0–100 numerical scale
- Separates **reliability of source** from **confidence in information** (credibility)
- Maps to NATO Admiralty Code:
  - Source reliability: A (Completely reliable) → F (Unreliable)
  - Information credibility: 1 (Confirmed) → 6 (Truth cannot be judged)
- Best practice: combine both into composite score (e.g., "A1" = highest trust)

**Key insight for Kerennnn**: Separating "how much I trust this source" from "how credible is this specific data point" allows more nuanced scoring. Currently Kerennnn merges both into a single weight.

### 2.3 OpenCTI Reliability & Confidence

**Docs**: docs.opencti.io/latest/usage/reliability-confidence/

**Architecture**:
- **Reliability**: organizational-level, set per entity author (NATO Admiralty A-F)
- **Confidence**: per-entity, 0–100 numerical scale
- **Max confidence level**: per-user/group governance cap
- Templates: Admiralty, Objective (Cannot be judged / Told / Induced / Deduced / Witnessed), Standard (Low/Med/High)

**Deduplication**: entities with higher confidence override lower ones on conflict.

**Key insight for Kerennnn**: The "Objective" confidence scale (Told → Induced → Deduced → Witnessed) maps well to TI source hierarchy:
- Witnessed = our own scan/enrichment
- Deduced = correlated across multiple sources
- Induced = single high-confidence source (VT, AbuseIPDB)
- Told = unverified feed data (OTX pulses)

### 2.4 Ermerins (2020) — Multi-Feed IoC Scoring

**Paper**: "Scoring model for IoCs by combining open intelligence feeds to reduce false positives" (OS3, cited 11×)

**Methodology**:
1. **Source confidence** per feed: based on extensiveness, timeliness, whitelist overlap
2. **Weighted average**: prioritizes high-confidence feeds in final score
3. **Time decay**: diminishing relevance of older IOCs
4. **Feed independence analysis**: measures overlap between feeds to detect redundancy

**Findings**:
- Sparse overlap between feeds is common — most IOCs appear in only 1–2 feeds
- Source confidence should be learned from historical accuracy, not assumed
- Whitelist overlap (IoCs appearing on known-good lists) is a strong false-positive signal

**Key insight for Kerennnn**: Track historical accuracy per source. If Abuse.ch consistently flags IPs that VT later clears, downweight Abuse.ch automatically.

### 2.5 Cyware Confidence Score Engine

**Platform**: Cyware Intel Exchange

**Parameters** (weighted sum → 0–100):
1. **Relations**: STIX relationship objects linking indicators
2. **Source Scoring**: reliability of feed provider
3. **External Enrichment**: third-party data boost
4. **Sightings**: frequency of observation across platforms

**Key insight for Kerennnn**: Sightings = how many times an IOC has been scanned/observed. More sightings = higher confidence. Currently Kerennnn doesn't track scan frequency as a positive signal.

### 2.6 Chatziamanetoglou (2025) — Weighted CTI Quality Criteria

**Paper**: "Weighted quality criteria for cyber threat intelligence assessment and prioritisation in the MISP data model" (cited 10×)

Extends MISP with weighted quality criteria for CTI prioritization. Demonstrates proof-of-concept implementation.

### 2.7 Community Insights (Reddit, Medium, Practitioners)

**r/threatintel, r/cybersecurity, r/blueteam consensus**:

1. **Multi-source corroboration is king**: "If 3+ independent sources flag the same IOC, it's almost certainly malicious. If only 1 flags it, be skeptical."

2. **Feed disagreement = signal**: "If a known-bad IOC keeps showing up clean across multiple feeds, that inconsistency itself might be worth flagging" — could indicate feed lag or evasion.

3. **Staleness is the #1 false positive cause**: "IPs rotate constantly. An IOC from 30 days ago is almost certainly reassigned." — Time decay is critical.

4. **Context > raw score**: "An IP flagged as C2 for Cobalt Strike in a financial sector campaign matters more to a bank than a generic 'malicious' score."

5. **Source hierarchy** (community consensus):
   - Tier 1: VirusTotal (crowd-sourced, 70+ engines), AbuseIPDB (direct abuse reports)
   - Tier 2: URLScan.io (active scanning), Abuse.ch/URLhaus (specialized)
   - Tier 3: OTX (community pulses, varying quality), generic OSINT feeds

6. **Practitioner recommendation**: "Never auto-block on a single source. Require ≥2 independent confirmations for automated action."

---

## 3. Gaps in Current Kerennnn Scoring

| Gap | Impact | Evidence |
|-----|--------|----------|
| **No time decay** | Stale IOCs score same as fresh | MISP paper, Ermerins, Reddit consensus |
| **Fixed weights** | VT overvalued for IPs, AbuseIPDB undervalued | Community tier hierarchy |
| **No cross-source bonus** | 1 source "malicious" vs 3 sources "malicious" scored similarly | All frameworks emphasize corroboration |
| **No sighting tracking** | Re-scanned IOCs don't get confidence boost | MISP sightings, Cyware engine |
| **No IOC-type-specific weights** | Hash reliability ≠ IP reliability ≠ domain reliability | MISP decay params differ by type |
| **No Bayesian updating** | Can't learn from historical accuracy | Ermerins, academic consensus |
| **Risk factors not source-weighted** | Enrichment bonus counts same as VT detection | STIX reliability/confidence separation |

---

## 4. Recommended Optimizations

### Priority 1: Time Decay (High Impact, Medium Effort)

**Approach**: MISP polynomial decay adapted for Kerennnn.

```javascript
// Per-IOC-type decay parameters
const DECAY_PARAMS = {
  ip:     { tau: 7 * 24,  alpha: 1.8 },  // 7 days, fast early decay
  domain: { tau: 14 * 24, alpha: 1.2 },  // 14 days, moderate
  hash:   { tau: 90 * 24, alpha: 0.5 },  // 90 days, slow decay
};

function decayMultiplier(hoursSinceLastSeen, type) {
  const { tau, alpha } = DECAY_PARAMS[type] || DECAY_PARAMS.ip;
  if (hoursSinceLastSeen >= tau) return 0;
  return Math.max(0, 1 - Math.pow(hoursSinceLastSeen / tau, alpha));
}

// Apply to confidence:
// finalConfidence = rawConfidence * decayMultiplier(hoursSinceLastSeen, type)
```

**Storage**: Add `last_seen` timestamp to `vt_ip_cache` and `vt_ioc_cache` tables. Update on each scan.

**Sighting reset**: When an IOC is re-scanned, reset `last_seen` → now, effectively giving it a "second life" (MISP approach).

### Priority 2: Cross-Source Corroboration Bonus (High Impact, Low Effort)

**Approach**: Boost confidence when multiple independent sources agree.

```javascript
function corroborationBonus(results) {
  const malSources = results.filter(r => r.verdict === 'malicious' && !r.skipped && !r.error);
  const susSources = results.filter(r => r.verdict === 'suspicious' && !r.skipped && !r.error);
  
  let bonus = 0;
  if (malSources.length >= 3) bonus += 15;  // Strong consensus
  else if (malSources.length >= 2) bonus += 10;  // Moderate consensus
  
  // Cross-type agreement (e.g., VT + AbuseIPDB + OTX all flag)
  const uniqueSourceTypes = new Set(malSources.map(r => r.source));
  if (uniqueSourceTypes.size >= 3) bonus += 5;  // Diverse agreement bonus
  
  return Math.min(bonus, 20);  // Cap at 20
}
```

**Rationale**: Reddit/industry consensus — 3+ independent confirmations = high confidence. Current floor system partially captures this but is weight-ratio based, not count based.

### Priority 3: IOC-Type-Specific Weights (Medium Impact, Low Effort)

**Approach**: Different weight distributions per IOC type.

```javascript
const WEIGHTS_BY_TYPE = {
  ip: {
    'VirusTotal':     0.25,
    'AbuseIPDB':      0.30,  // Best IP-specific source
    'Abuse.ch':       0.15,
    'AlienVault OTX': 0.10,
    'Enrichment':     0.00,  // context only
  },
  domain: {
    'VirusTotal':     0.25,
    'Abuse.ch':       0.25,
    'URLScan.io':     0.25,  // Best domain-specific source
    'AlienVault OTX': 0.15,
    'Enrichment':     0.00,
  },
  hash: {
    'VirusTotal':     0.50,  // Dominant for hashes
    'AlienVault OTX': 0.30,
    // Other sources don't serve hashes
  },
};
```

**Rationale**: AbuseIPDB is the strongest IP source (direct abuse reports from network operators). URLScan is the strongest domain source (active page scanning). VT is dominant for hashes. Current flat weights don't reflect this.

### Priority 4: Bayesian Posterior Aggregation (High Impact, High Effort)

**Approach**: Replace weighted average with log-odds fusion.

```javascript
// Convert each source's verdict to a likelihood ratio
function verdictToLikelihood(verdict, sourceReliability) {
  const baseLR = {
    malicious:  10.0,   // 10:1 in favor of malicious
    suspicious:  3.0,   // 3:1 in favor
    unknown:     1.0,   // no information
    clean:       0.3,   // 3:1 against malicious
  };
  const lr = baseLR[verdict] ?? 1.0;
  // Adjust by source reliability
  return Math.pow(lr, sourceReliability);
}

// Combine via log-odds
function bayesianConfidence(results, priorOdds = 0.1) {
  let logOdds = Math.log(priorOdds);
  for (const r of results) {
    if (r.skipped || r.error) continue;
    const reliability = r.weight;  // use existing weight as reliability proxy
    const lr = verdictToLikelihood(r.verdict, reliability);
    logOdds += Math.log(lr);
  }
  const posteriorOdds = Math.exp(logOdds);
  return Math.round((posteriorOdds / (1 + posteriorOdds)) * 100);
}
```

**Rationale**: Bayesian fusion is mathematically optimal for combining independent evidence. It naturally handles: source disagreement (moderate signals cancel out), strong consensus (compounds exponentially), and prior belief (base rate of maliciousness).

**Tradeoff**: Less interpretable than weighted average. Keep current approach as `baselineConfidence` for display, use Bayesian as `optimizedConfidence` for automated actions.

### Priority 5: Source Reliability Tracking (Medium Impact, Medium Effort)

**Approach**: Learn source accuracy from historical data.

```javascript
// Track per-source accuracy in DB
// Table: source_reliability (source, ioc_type, true_positive, false_positive, last_updated)

function sourceReliability(source, iocType) {
  // Query historical accuracy
  const tp = stats.true_positive || 0;
  const fp = stats.false_positive || 0;
  const total = tp + fp;
  if (total < 10) return 0.5;  // insufficient data, use neutral
  return tp / total;  // precision = reliability
}
```

**Feedback loop**: When an analyst marks an IOC as false positive in the UI, record which sources flagged it → update reliability scores.

**Rationale**: Ermerins (2020) — source confidence should be learned, not assumed. MISP uses per-organization trust levels.

### Priority 6: Sighting-Based Confidence Boost (Low Impact, Low Effort)

**Approach**: Track scan frequency as a positive signal.

```javascript
function sightingBoost(scanCount) {
  if (scanCount >= 10) return 10;  // frequently investigated = noteworthy
  if (scanCount >= 5) return 5;
  if (scanCount >= 2) return 3;    // re-scanned = analyst interest
  return 0;
}
```

**Rationale**: Cyware engine — sightings indicate analyst interest and cross-platform observation. An IOC that 10 analysts have independently investigated is more likely to be a true positive.

---

## 5. Proposed Final Formula

Combining all optimizations:

```
sourceConfidence = bayesianConfidence(results)        // Priority 4
corroboration    = corroborationBonus(results)         // Priority 2
riskBonus        = min(sum(risk_factors.bonus), 25)    // existing
sightingBonus    = sightingBoost(scanCount)            // Priority 6
rawConfidence    = min(100, sourceConfidence + corroboration + riskBonus + sightingBonus)
decay            = decayMultiplier(hoursSinceLastSeen)  // Priority 1
finalConfidence  = round(rawConfidence * decay)
```

### Verdict Thresholds

| Confidence | Verdict     | Action                          |
|-----------|-------------|--------------------------------|
| ≥ 70      | MALICIOUS   | Alert, auto-block (if enabled)  |
| ≥ 40      | SUSPICIOUS  | Alert, manual review            |
| ≥ 15      | LOW RISK    | Log, no alert                   |
| < 15      | CLEAN       | No action                       |

### Guard Rails

- **Minimum sources**: require ≥2 active (non-skipped, non-error) sources for MALICIOUS verdict
- **Single-source cap**: if only 1 source responded, cap confidence at 50 regardless of score
- **Stale IOC override**: if `last_seen > 30 days` for IP/domain, cap at SUSPICIOUS (40) max
- **Analyst override**: manual verdict (true/false positive) always takes precedence

---

## 6. Implementation Roadmap

| Phase | Optimization | Effort | Impact | Files Changed |
|-------|-------------|--------|--------|---------------|
| 1     | Time decay  | Medium | High   | `correlate.js`, DB schema, `vt.js` |
| 2     | Cross-source bonus | Low | High | `correlate.js` |
| 3     | IOC-type weights | Low | Medium | `correlate.js` |
| 4     | Bayesian aggregation | High | High | `correlate.js`, new module |
| 5     | Source reliability tracking | Medium | Medium | DB schema, `correlate.js`, UI |
| 6     | Sighting boost | Low | Low | DB schema, `correlate.js` |

**Recommended order**: 2 → 3 → 1 → 4 → 6 → 5

Phases 2 and 3 are quick wins with immediate accuracy improvement. Phase 1 requires DB migration. Phase 4 is the biggest payoff but needs careful testing. Phase 5 requires analyst feedback UI.

---

## 7. References

### Academic Papers
1. Dulaunoy, A. et al. (2018). "An Indicator Scoring Method for MISP Platforms." TNC18. https://tnc18.geant.org/getfile/tnc18_paper_MISPCW.pdf
2. Ermerins, J. (2020). "Scoring model for IoCs by combining open intelligence feeds to reduce false positives." OS3. https://rp.os3.nl/2019-2020/p55/report.pdf
3. Chatziamanetoglou, D. (2025). "Weighted quality criteria for cyber threat intelligence assessment." https://d-nb.info/1374617113/34
4. Villalón-Huerta, A. et al. (2022). "Key Requirements for the Detection and Sharing of IOCs." Electronics 11(3), 416. https://www.mdpi.com/2079-9292/11/3/416
5. Girard, A. (2025). "The Evolution of Threat Intelligence: From IOC Feeds to Context-Driven Detection." https://www.adriengirard.com/blog/the-evolution-of-threat-intelligence-from-ioc-feeds-to-context-driven-detection

### Industry Standards
6. OASIS (2021). STIX Version 2.1 — Confidence. https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.pdf
7. MISP Best Practices — Expressing Confidence. https://github.com/MISP/best-practices-in-threat-intelligence/blob/master/best-practices/expressing-confidence.adoc
8. MISP (2022). "Curate events with an organisation confidence level." https://www.misp-project.org/2022/11/14/curation-with-org-confidence-level.html/
9. OpenCTI — Reliability and Confidence. https://docs.opencti.io/latest/usage/reliability-confidence/
10. Cyware — Confidence Scoring in Threat Intelligence. https://www.cyware.com/resources/security-guides/what-is-confidence-scoring-in-threat-intelligence

### Community
11. r/threatintel — "How useful are threat intelligence feeds in your work?" https://www.reddit.com/r/threatintel/comments/1qcv428/
12. r/threatintel — "How do you assess the efficacy of threat intelligence feeds?" https://www.reddit.com/r/threatintel/comments/1f0mbke/
13. r/cybersecurity — "Threat intel feeds… is it just me or are they all starting to…" https://www.reddit.com/r/cybersecurity/comments/1m6u5hf/
14. r/CyberSecurityAdvice — "Using 'bad' data to improve threat detection" https://www.reddit.com/r/CyberSecurityAdvice/comments/1tfabb4/

### Tools Referenced
15. MISP — https://github.com/MISP/MISP
16. OpenCTI — https://github.com/OpenCTI-Platform/opencti
17. TheHive/Cortex — https://github.com/TheHive-Project/TheHive
