/**
 * Infrastructure Pivoting Engine
 * Uses VirusTotal Relationships API to discover related malicious infrastructure
 * from a single IOC — no AI required.
 */
import axios from 'axios';

const VT_BASE = 'https://www.virustotal.com/api/v3';

const vtGet = async (path, params = {}) => {
    try {
        const res = await axios.get(`${VT_BASE}${path}`, {
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
            params: { limit: 20, ...params },
            validateStatus: () => true,
            timeout: 8000
        });
        if (res.status === 200) return res.data?.data || [];
        return [];
    } catch {
        return [];
    }
};

// Risk level derived from VT detection ratio
const inferRisk = (attributes) => {
    const stats = attributes?.last_analysis_stats;
    if (!stats) return 'unknown';
    const detected = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = detected + (stats.harmless || 0) + (stats.undetected || 0);
    if (total === 0) return 'unknown';
    const ratio = detected / total;
    if (ratio > 0.4 || detected > 5) return 'critical';
    if (ratio > 0.15 || detected > 2) return 'high';
    if (detected > 0) return 'medium';
    return 'low';
};

const makeNode = (id, type, label, attributes = {}, meta = {}) => ({
    id,
    type,   // ip | domain | file | certificate
    label: label.length > 40 ? label.substring(0, 37) + '...' : label,
    full_label: label,
    risk: inferRisk(attributes),
    detections: (attributes?.last_analysis_stats?.malicious || 0) + (attributes?.last_analysis_stats?.suspicious || 0),
    total_engines: Object.values(attributes?.last_analysis_stats || {}).reduce((a, b) => a + b, 0),
    first_seen: attributes?.first_submission_date || attributes?.creation_date || null,
    ...meta
});

const makeEdge = (from, to, relation) => ({ from, to, relation });

/**
 * Pivots from an IP to related domains, communicating malware, and SSL certs
 */
const pivotFromIP = async (ip) => {
    const nodes = [];
    const edges = [];
    const seenIds = new Set([ip]);

    // 1. DNS Resolutions — domains hosted on this IP
    const resolutions = await vtGet(`/ip_addresses/${ip}/resolutions`);
    for (const r of resolutions.slice(0, 15)) {
        const domainId = r.attributes?.host_name;
        if (!domainId || seenIds.has(domainId)) continue;
        seenIds.add(domainId);
        nodes.push(makeNode(domainId, 'domain', domainId, r.attributes, {
            resolved_date: r.attributes?.date
        }));
        edges.push(makeEdge(ip, domainId, 'resolves_to'));
    }

    // 2. Communicating Files — malware beaconing to this IP
    const files = await vtGet(`/ip_addresses/${ip}/communicating_files`);
    for (const f of files.slice(0, 10)) {
        const fileId = f.id;
        if (!fileId || seenIds.has(fileId)) continue;
        seenIds.add(fileId);
        nodes.push(makeNode(fileId, 'file',
            f.attributes?.meaningful_name || f.attributes?.names?.[0] || fileId.substring(0, 16),
            f.attributes, { sha256: fileId, family: f.attributes?.popular_threat_classification?.suggested_threat_label }
        ));
        edges.push(makeEdge(fileId, ip, 'communicates_with'));
    }

    return { nodes, edges, seenIds };
};

/**
 * Pivots from a Domain to related IPs, SSL certs, and communicating files
 */
const pivotFromDomain = async (domain) => {
    const nodes = [];
    const edges = [];
    const seenIds = new Set([domain]);

    // 1. DNS Resolutions — IPs this domain has pointed to
    const resolutions = await vtGet(`/domains/${domain}/resolutions`);
    for (const r of resolutions.slice(0, 15)) {
        const ipId = r.attributes?.ip_address;
        if (!ipId || seenIds.has(ipId)) continue;
        seenIds.add(ipId);
        nodes.push(makeNode(ipId, 'ip', ipId, r.attributes, {
            country: r.attributes?.country,
            asn: r.attributes?.asn
        }));
        edges.push(makeEdge(domain, ipId, 'resolves_to'));
    }

    // 2. Historical SSL Certificates — find cert fingerprints
    const certs = await vtGet(`/domains/${domain}/historical_ssl_certificates`);
    for (const cert of certs.slice(0, 5)) {
        const certId = cert.id;
        if (!certId || seenIds.has(certId)) continue;
        seenIds.add(certId);
        const cn = cert.attributes?.subject?.CN || cert.attributes?.issuer?.O || certId.substring(0, 16);
        nodes.push(makeNode(certId, 'certificate', cn, {}, {
            thumbprint: certId,
            expires: cert.attributes?.validity?.not_after,
            issuer: cert.attributes?.issuer?.O
        }));
        edges.push(makeEdge(domain, certId, 'uses_cert'));
    }

    // 3. Communicating Files
    const files = await vtGet(`/domains/${domain}/communicating_files`);
    for (const f of files.slice(0, 8)) {
        const fileId = f.id;
        if (!fileId || seenIds.has(fileId)) continue;
        seenIds.add(fileId);
        nodes.push(makeNode(fileId, 'file',
            f.attributes?.meaningful_name || f.attributes?.names?.[0] || fileId.substring(0, 16),
            f.attributes, { sha256: fileId, family: f.attributes?.popular_threat_classification?.suggested_threat_label }
        ));
        edges.push(makeEdge(fileId, domain, 'communicates_with'));
    }

    return { nodes, edges, seenIds };
};

/**
 * Secondary pivot: given a found domain, discover shared-cert siblings
 * (other domains using the same SSL cert = same infrastructure)
 */
const pivotCertSiblings = async (domainId, certId, existingSeenIds) => {
    const nodes = [];
    const edges = [];
    
    const siblings = await vtGet(`/ssl_certificates/${certId}/domains`);
    for (const s of siblings.slice(0, 8)) {
        const sibId = s.id;
        if (!sibId || existingSeenIds.has(sibId) || sibId === domainId) continue;
        existingSeenIds.add(sibId);
        nodes.push(makeNode(sibId, 'domain', sibId, s.attributes, { shared_cert: certId }));
        edges.push(makeEdge(certId, sibId, 'shared_cert_sibling'));
    }
    return { nodes, edges };
};

/**
 * Main export: full infrastructure pivot
 */
export const pivotInfrastructure = async (ioc, type) => {
    const isIP = type === 'ip';
    const rootNode = makeNode(ioc, type, ioc, {}, { is_root: true });

    let primary;
    if (isIP) {
        primary = await pivotFromIP(ioc);
    } else {
        primary = await pivotFromDomain(ioc);
    }

    const allNodes = [rootNode, ...primary.nodes];
    const allEdges = [...primary.edges];

    // Secondary pivot: for each SSL certificate found, discover shared-cert siblings
    const certNodes = primary.nodes.filter(n => n.type === 'certificate');
    for (const cert of certNodes.slice(0, 3)) {
        // find the domain that owns this cert
        const ownerEdge = primary.edges.find(e => e.to === cert.id);
        if (ownerEdge) {
            const siblings = await pivotCertSiblings(ownerEdge.from, cert.id, primary.seenIds);
            allNodes.push(...siblings.nodes);
            allEdges.push(...siblings.edges);
        }
    }

    return {
        root: ioc,
        type,
        stats: {
            total_nodes: allNodes.length,
            ips: allNodes.filter(n => n.type === 'ip').length,
            domains: allNodes.filter(n => n.type === 'domain').length,
            files: allNodes.filter(n => n.type === 'file').length,
            certificates: allNodes.filter(n => n.type === 'certificate').length,
            malicious_nodes: allNodes.filter(n => n.risk === 'critical' || n.risk === 'high').length
        },
        nodes: allNodes,
        edges: allEdges
    };
};
