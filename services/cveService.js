/**
 * CVE Lookup Service
 * Extracts CVE IDs from raw threat intel data (no AI dependency)
 * and enriches them via the NIST NVD API (free, no key required).
 */
import axios from 'axios';

// In-memory cache for NVD lookups (avoid hammering free API)
const cveCache = new Map();
const CACHE_TTL = 1000 * 60 * 60 * 4; // 4 hours

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;

/**
 * Extract CVE IDs from all raw, verified (non-AI) sources.
 * Only scans actual API response data — never scans AI output.
 */
export const extractCVEsFromRawData = (vtData, tfData, otxData) => {
    const cveSet = new Set();
    const provenance = {}; // Track where each CVE was found

    const addCVE = (cveId, source) => {
        const id = cveId.toUpperCase();
        cveSet.add(id);
        if (!provenance[id]) provenance[id] = [];
        if (!provenance[id].includes(source)) provenance[id].push(source);
    };

    // Source 1: VirusTotal sandbox verdicts
    if (vtData?.sandbox_verdicts) {
        const text = JSON.stringify(vtData.sandbox_verdicts);
        const matches = text.match(CVE_REGEX);
        if (matches) matches.forEach(m => addCVE(m, 'VirusTotal Sandbox'));
    }

    // Source 2: VirusTotal Sigma analysis results (real engine rules, not our generated ones)
    if (vtData?.sigma_analysis_results) {
        vtData.sigma_analysis_results.forEach(rule => {
            const text = `${rule.rule_title || ''} ${rule.rule_description || ''} ${JSON.stringify(rule.match_context || '')}`;
            const matches = text.match(CVE_REGEX);
            if (matches) matches.forEach(m => addCVE(m, `VT Sigma: ${rule.rule_title || 'Rule'}`));
        });
    }

    // Source 3: VirusTotal crowdsourced IDS results
    if (vtData?.crowdsourced_ids_results) {
        vtData.crowdsourced_ids_results.forEach(ids => {
            const text = `${ids.rule_msg || ''} ${ids.rule_raw || ''} ${ids.alert_context || ''}`;
            const matches = text.match(CVE_REGEX);
            if (matches) matches.forEach(m => addCVE(m, `IDS Alert: ${ids.rule_msg || 'Rule'}`));
        });
    }

    // Source 4: VirusTotal crowdsourced YARA results
    if (vtData?.crowdsourced_yara_results) {
        vtData.crowdsourced_yara_results.forEach(yara => {
            const text = `${yara.rule_name || ''} ${yara.description || ''} ${yara.source || ''}`;
            const matches = text.match(CVE_REGEX);
            if (matches) matches.forEach(m => addCVE(m, `YARA: ${yara.rule_name || 'Rule'}`));
        });
    }

    // Source 5: VirusTotal tags
    if (vtData?.tags) {
        const text = vtData.tags.join(' ');
        const matches = text.match(CVE_REGEX);
        if (matches) matches.forEach(m => addCVE(m, 'VirusTotal Tags'));
    }

    // Source 6: ThreatFox data
    if (tfData && Array.isArray(tfData)) {
        tfData.forEach(hit => {
            const text = `${hit.malware_printable || ''} ${hit.threat_type_desc || ''} ${(hit.tags || []).join(' ')} ${hit.reference || ''}`;
            const matches = text.match(CVE_REGEX);
            if (matches) matches.forEach(m => addCVE(m, 'ThreatFox'));
        });
    }

    // Source 7: AlienVault OTX pulses
    if (otxData?.pulse_info?.pulses) {
        otxData.pulse_info.pulses.forEach(pulse => {
            const text = `${pulse.name || ''} ${pulse.description || ''} ${(pulse.tags || []).join(' ')}`;
            const matches = text.match(CVE_REGEX);
            if (matches) matches.forEach(m => addCVE(m, `OTX Pulse: ${pulse.name || 'Pulse'}`));
        });
    }

    return { cveIds: [...cveSet], provenance };
};

/**
 * Look up a single CVE from the NIST NVD API.
 */
export const lookupCVE = async (cveId) => {
    const cached = cveCache.get(cveId);
    if (cached && Date.now() - cached.ts < CACHE_TTL) {
        return cached.data;
    }

    try {
        const res = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
            timeout: 8000,
            headers: { 'User-Agent': 'ThreatIntelPlatform/1.0' }
        });

        if (res.data?.vulnerabilities?.[0]?.cve) {
            const cve = res.data.vulnerabilities[0].cve;

            // Extract CVSS score (try v3.1 first, then v3.0, then v2)
            const metricsV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
            const metricsV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            const metricsV2  = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
            const cvss = metricsV31 || metricsV30 || metricsV2;

            const data = {
                id: cve.id,
                description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available.',
                published: cve.published,
                lastModified: cve.lastModified,
                cvssScore: cvss?.baseScore || null,
                cvssVector: cvss?.vectorString || null,
                severity: cvss?.baseSeverity || (metricsV2 ? getSeverityFromV2(metricsV2.baseScore) : null),
                exploitabilityScore: cve.metrics?.cvssMetricV31?.[0]?.exploitabilityScore ||
                                     cve.metrics?.cvssMetricV30?.[0]?.exploitabilityScore || null,
                impactScore: cve.metrics?.cvssMetricV31?.[0]?.impactScore ||
                             cve.metrics?.cvssMetricV30?.[0]?.impactScore || null,
                weaknesses: cve.weaknesses?.map(w => w.description?.find(d => d.lang === 'en')?.value).filter(Boolean) || [],
                references: cve.references?.slice(0, 5).map(r => ({ url: r.url, source: r.source })) || [],
                validated: true
            };

            cveCache.set(cveId, { data, ts: Date.now() });
            return data;
        }
    } catch (e) {
        console.error(`NVD lookup failed for ${cveId}:`, e.message);
    }

    return null;
};

/**
 * Batch enrich CVE IDs via NVD.
 * NVD rate limit: 5 requests per 30 seconds without API key.
 */
export const enrichCVEs = async (cveIds, provenance = {}) => {
    const results = [];

    for (const cveId of cveIds.slice(0, 10)) { // Cap at 10 CVEs to avoid timeout
        const data = await lookupCVE(cveId);
        if (data) {
            results.push({
                ...data,
                sources: provenance[cveId] || ['Unknown']
            });
        }
        // Rate limit: NVD allows ~5 req/30s without key
        await new Promise(r => setTimeout(r, 600));
    }

    return results.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
};

function getSeverityFromV2(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}
