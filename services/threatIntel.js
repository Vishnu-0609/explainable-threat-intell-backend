import axios from 'axios';
import { analyzeWithAI } from './aiService.js';
import { generateRules } from './ruleGenerator.js';

// Helper to check if a string is an IP address
const isIP = (str) => {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(str);
};

// Helper to check if a string is a domain (very basic)
const isDomain = (str) => {
    return str.includes('.') && !isIP(str) && !str.includes('http');
};

const getDetections = (last_analysis_stats) => {
    if (!last_analysis_stats) return { detected: 0, total: 0 };
    const detected = last_analysis_stats.malicious + last_analysis_stats.suspicious;
    const total = detected + last_analysis_stats.harmless + last_analysis_stats.undetected;
    return { detected, total };
}

const calculateRisk = (detected, total, otherRiskIndicators = 0) => {
    if (total === 0 && otherRiskIndicators === 0) return 'low';
    const ratio = (detected + otherRiskIndicators) / (total + 10); // Simple weighting
    if (ratio > 0.5 || detected > 5) return 'critical';
    if (ratio > 0.2 || detected > 2) return 'high';
    if (detected > 0) return 'medium';
    return 'low';
};

// --- Independent Service Fetchers ---

const fetchVirusTotal = async (ioc, sourceType) => {
    try {
        let vtEndpoint = '';
        if (sourceType === 'ip') vtEndpoint = `ip_addresses/${ioc}`;
        else if (sourceType === 'domain') vtEndpoint = `domains/${ioc}`;
        else vtEndpoint = `files/${ioc}`;

        if (ioc.startsWith('http')) {
            const urlId = Buffer.from(ioc).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
            vtEndpoint = `urls/${urlId}`;
        }

        const response = await axios.get(`https://www.virustotal.com/api/v3/${vtEndpoint}`, {
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
            validateStatus: () => true
        });

        if (response.status === 200 && response.data.data) {
            return response.data.data.attributes;
        }
    } catch (e) {
        console.error('VirusTotal Error:', e.message);
    }
    return null;
};

const fetchAbuseIPDB = async (ioc, sourceType) => {
    if (sourceType !== 'ip') return null;
    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ioc, maxAgeInDays: 90 },
            headers: {
                'Key': process.env.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        });
        return response.data?.data || null;
    } catch (e) {
        console.error('AbuseIPDB Error:', e.message);
        return null;
    }
};

const fetchThreatFox = async (ioc) => {
    try {
        const response = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
            query: 'search_ioc',
            search_term: ioc
        }, {
            headers: {
                'Auth-Key': process.env.THREATFOX_API_KEY,
                'Content-Type': 'application/json'
            }
        });

        // console.log(response.data);

        if (response.data && response.data.query_status === 'ok') {
            return response.data.data; // Returns array of hits
        }
    } catch (e) {
        console.error('ThreatFox Error', e.message);
    }
    return null;
};

const fetchOTX = async (ioc, sourceType) => {
    try {
        let otxType = 'IPv4';
        if (sourceType === 'domain') otxType = 'domain';
        else if (sourceType === 'hash_or_url') otxType = 'file';

        const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${ioc}/general`, {
            headers: { 'X-OTX-API-KEY': process.env.ALIENVAULT_API_KEY },
            validateStatus: () => true
        });

        // console.log(response.data);

        if (response.status === 200) {
            return response.data;
        }
    } catch (e) {
        console.error('AlienVault Error', e.message);
    }
    return null;
}

// --- Main Aggregator ---

export const analyzeIOC = async (ioc) => {
    const results = {
        ioc: {
            value: ioc,
            type: 'unknown',
            risk_level: 'unknown',
            confidence: 0,
            status: 'active',
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            explainability: 'Analysis in progress...'
        },
        behaviors: [],
        techniques: [],
        countermeasures: [],
        evidence: [],
        details: { // Universal details container
            sources: {}
        }
    };

    const sourceType = isIP(ioc) ? 'ip' : isDomain(ioc) ? 'domain' : 'hash_or_url';
    results.ioc.type = sourceType;

    // Execute in Parallel
    const [vtResult, abuseResult, tfResult, otxResult] = await Promise.allSettled([
        fetchVirusTotal(ioc, sourceType),
        fetchAbuseIPDB(ioc, sourceType),
        fetchThreatFox(ioc),
        fetchOTX(ioc, sourceType)
    ]);

    // --- Process VirusTotal ---
    if (vtResult.status === 'fulfilled' && vtResult.value) {
        const data = vtResult.value;
        results.details.sources.virus_total = data; // Raw data reference

        const stats = data.last_analysis_stats;
        const { detected, total } = getDetections(stats);
        const risk = calculateRisk(detected, total);

        results.ioc.risk_level = risk;
        results.ioc.confidence = Math.min(100, Math.round((detected / total) * 100 * 1.5)) || 0;

        results.ioc.explainability = `VirusTotal analysis statistics: ${detected}/${total} engines detected this as malicious. `;
        if (data.reputation) results.ioc.explainability += `Community reputation score is ${data.reputation}. `;

        results.evidence.push({
            source_name: 'VirusTotal',
            evidence_type: 'reputation',
            evidence_data: { detections: detected, total: total },
            timestamp: new Date().toISOString()
        });

        // Vendors
        const resultsMap = data.last_analysis_results;
        if (resultsMap) {
            results.vendor_analysis = [];
            Object.keys(resultsMap).forEach(vendor => {
                const res = resultsMap[vendor];
                results.vendor_analysis.push({
                    name: vendor,
                    category: res.category,
                    result: res.result,
                    engine_version: res.engine_version
                });

                if (res.category === 'malicious' && results.behaviors.length < 5) {
                    results.behaviors.push({
                        description: `${vendor} detected: ${res.result}`,
                        timestamp: new Date().toISOString()
                    });
                }
            });
            results.vendor_analysis.sort((a, b) => {
                if (a.category === 'malicious' && b.category !== 'malicious') return -1;
                if (a.category !== 'malicious' && b.category === 'malicious') return 1;
                return 0;
            });
        }

        // Enrichment Details
        results.details.basic_properties = {
            md5: data.md5,
            sha1: data.sha1,
            sha256: data.sha256,
            vhash: data.vhash,
            authentihash: data.authentihash,
            imphash: data.pe_info?.imphash,
            ssdeep: data.ssdeep,
            tlsh: data.tlsh,
            file_type: data.type_description,
            magic: data.magic,
            trid: data.trid,
            file_size: data.size
        };
        results.details.popularity_ranks = data.popularity_ranks;
        results.details.last_dns_records = data.last_dns_records;
        results.details.last_https_certificate = data.last_https_certificate;
        results.details.jarm = data.jarm;
        results.details.whois = data.whois;
        results.details.whois_date = data.whois_date;
        results.details.names = data.names;
        results.details.signature_info = data.signature_info;
        results.details.pe_info = data.pe_info;
        results.details.history = {
            creation_time: data.creation_date,
            first_seen: data.first_seen_itw_date,
            first_submission: data.first_submission_date,
            last_submission: data.last_submission_date,
            last_analysis: data.last_analysis_date,
            expiration_date: data.whois_map?.expiration_date
        };

        // URL Specific Details
        results.details.categories = data.categories;
        results.details.http_response = {
            final_url: data.last_final_url,
            serving_ip_address: data.last_serving_ip_address,
            status_code: data.last_http_response_code,
            body_length: data.last_http_response_content_length,
            body_sha256: data.last_http_response_content_sha256
        };
        results.details.http_headers = data.last_http_response_headers;
        results.details.html_info = {
            title: data.title,
            meta_tags: data.html_meta
        };
        results.details.redirection_chain = data.redirection_chain;
    }

    // --- Process AbuseIPDB ---
    if (abuseResult.status === 'fulfilled' && abuseResult.value) {
        const data = abuseResult.value;
        results.details.sources.abuseipdb = data;

        if (data.abuseConfidenceScore > results.ioc.confidence) {
            results.ioc.confidence = data.abuseConfidenceScore;
            if (data.abuseConfidenceScore > 50) results.ioc.risk_level = 'high';
            if (data.abuseConfidenceScore > 80) results.ioc.risk_level = 'critical';
        }

        results.ioc.explainability += `AbuseIPDB Confidence Score: ${data.abuseConfidenceScore}%. Total Reports: ${data.totalReports}. `;
        results.evidence.push({
            source_name: 'AbuseIPDB',
            evidence_type: 'reputation',
            evidence_data: { confidence: data.abuseConfidenceScore, reports: data.totalReports },
            timestamp: new Date().toISOString()
        });
    }

    // --- Process ThreatFox ---
    if (tfResult.status === 'fulfilled' && tfResult.value && tfResult.value.length > 0) {
        const hits = tfResult.value;
        results.details.sources.threatfox = hits;

        const hit = hits[0];
        results.ioc.risk_level = 'critical';
        results.ioc.confidence = 100;

        results.ioc.explainability += `Found in ThreatFox database (${hit.malware_printable}). `;
        results.evidence.push({
            source_name: 'ThreatFox',
            evidence_type: 'threat_intel',
            evidence_data: { malware: hit.malware_printable, threat_type: hit.threat_type },
            timestamp: new Date().toISOString()
        });

        if (hit.tags) {
            hit.tags.forEach(tag => {
                results.behaviors.push({
                    description: `ThreatFox Tag: ${tag}`,
                    timestamp: new Date().toISOString()
                });
            });
        }
    }

    // --- Process OTX ---
    // console.log('OTX Result:', otxResult.status);
    // console.log('OTX Value:', otxResult.value);
    if (otxResult.status === 'fulfilled' && otxResult.value) {
        const data = otxResult.value;
        results.details.sources.otx = data;

        if (data.pulse_info && data.pulse_info.count > 0) {
            results.ioc.explainability += `Associated with ${data.pulse_info.count} OTX pulses. `;
            if (results.ioc.risk_level === 'unknown' || results.ioc.risk_level === 'low') {
                results.ioc.risk_level = 'medium';
            }
            results.evidence.push({
                source_name: 'AlienVault OTX',
                evidence_type: 'threat_intel',
                evidence_data: { pulse_count: data.pulse_info.count },
                timestamp: new Date().toISOString()
            });
        }
    }

    // --- Dynamic MITRE ATT&CK Extraction (Vendor-Provided) ---
    // Extract real-time techniques from VirusTotal Sandbox Verdicts
    console.log(results.details.sources.virus_total);
    if (results.details.sources.virus_total?.sandbox_verdicts) {
        const verdicts = results.details.sources.virus_total.sandbox_verdicts;
        Object.keys(verdicts).forEach(sandbox => {
            const verdict = verdicts[sandbox];
            if (verdict.attack_techniques) {
                verdict.attack_techniques.forEach(tech => {
                    results.techniques.push({
                        id: tech.id,
                        name: tech.category_description || tech.id, // Fallback to ID if no description
                        description: `Detected by ${sandbox}: ${tech.severity} severity`, // Contextual description
                        severity: tech.severity
                    });
                });
            }
        });

        // Deduplicate Techniques by ID
        const uniqueTechniques = [];
        const seenIds = new Set();
        results.techniques.forEach(tech => {
            if (!seenIds.has(tech.id)) {
                seenIds.add(tech.id);
                uniqueTechniques.push(tech);
            }
        });
        results.techniques = uniqueTechniques;
    }

    // --- AI-Powered Sophistication & Hybrid Mapping ---
    const aiResult = await analyzeWithAI(results);

    if (aiResult) {
        // Use AI Executive Summary
        if (aiResult.summary) {
            results.ioc.explainability = aiResult.summary;
        }

        // Pass new ETI (Explainable Threat Intelligence) fields
        results.ioc.reasoning = aiResult.reasoning || null;
        results.ioc.attack_pattern = aiResult.pattern || null;
        results.ioc.ai_source = aiResult.source || null;

        // Populate Countermeasures
        if (aiResult.countermeasures) {
            results.countermeasures = aiResult.countermeasures;
        }

        // Merge AI-Inferred Techniques
        if (aiResult.inferred_techniques) {
            aiResult.inferred_techniques.forEach(tech => {
                if (!results.techniques.find(existing => existing.id === tech.id)) {
                    results.techniques.push({ ...tech, source: 'AI Inferred' });
                }
            });
        }
    }

    // Final cleanup
    if (results.ioc.risk_level === 'unknown') results.ioc.risk_level = 'low';
    if (!results.ioc.explainability || results.ioc.explainability === 'Analysis in progress...') {
        results.ioc.explainability = 'No significant threat intelligence found for this indicator.';
    }

    // Generate Actionable Detection Rules (Differentiator)
    results.detection_rules = generateRules(results.ioc, results, results.techniques);

    return results;
};

export const fetchRecentFeeds = async () => {
    const feeds = [];

    const [tfResult, abuseResult, mbResult] = await Promise.allSettled([
        axios.post('https://threatfox-api.abuse.ch/api/v1/', {
            query: 'get_iocs',
            days: 1
        }, {
            headers: {
                'Auth-Key': process.env.THREATFOX_API_KEY,
                'Content-Type': 'application/json'
            }
        }),
        axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
            params: { confidenceMinimum: 90, limit: 50 },
            headers: {
                'Key': process.env.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        }),
        axios.post('https://mb-api.abuse.ch/api/v1/', new URLSearchParams({
            query: 'get_recent',
            selector: '100'
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        })
    ]);

    // Process MalwareBazaar (Hashes)
    if (mbResult.status === 'fulfilled' && mbResult.value.data?.query_status === 'ok') {
        const samples = mbResult.value.data.data;
        samples.forEach(sample => {
            feeds.push({
                ioc: sample.sha256_hash,
                type: 'sha256_hash',
                risk: 'high',
                pattern: sample.signature || 'Universal Malware',
                summary: `MalwareBazaar: ${sample.file_type_guess} payload detected.`,
                source: 'MalwareBazaar',
                timestamp: sample.first_seen || new Date().toISOString()
            });
        });
    }

    // Process ThreatFox
    if (tfResult.status === 'fulfilled' && tfResult.value.data?.query_status === 'ok') {
        const iocs = tfResult.value.data.data.slice(0, 50);
        iocs.forEach(ioc => {
            feeds.push({
                ioc: ioc.ioc,
                type: ioc.threat_type,
                risk: 'high',
                pattern: ioc.malware_printable || 'Unknown Malware',
                summary: `ThreatFox detection: ${ioc.threat_type_desc}`,
                source: 'ThreatFox',
                timestamp: ioc.first_seen || new Date().toISOString()
            });
        });
    }

    // Process AbuseIPDB
    if (abuseResult.status === 'fulfilled' && abuseResult.value.data?.data) {
        const iocs = abuseResult.value.data.data;
        iocs.forEach(ioc => {
            feeds.push({
                ioc: ioc.ipAddress,
                type: 'ip',
                risk: ioc.abuseConfidenceScore > 90 ? 'critical' : 'high',
                pattern: 'Abusive IP',
                summary: `AbuseIPDB reports: ${ioc.totalReports}. Confidence: ${ioc.abuseConfidenceScore}%`,
                source: 'AbuseIPDB',
                timestamp: new Date().toISOString() // Blacklist doesn't always have per-entry timestamp
            });
        });
    }

    // Sort by timestamp if available, otherwise keep order
    return feeds.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 100);
};
