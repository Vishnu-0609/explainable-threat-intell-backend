/**
 * Automated Detection Engineering Service
 * Generates Sigma and YARA rules based on threat intelligence data.
 */

export const generateRules = (ioc, data, techniques = []) => {
    const rules = [];

    // 1. Generate Sigma Rule (Generic SIEM)
    rules.push({
        type: 'Sigma',
        title: `Suspicious ${ioc.type.toUpperCase()} - ${ioc.value}`,
        format: 'yaml',
        content: generateSigmaContent(ioc, data, techniques)
    });

    // 2. Generate YARA Rule (For Hashes)
    if (ioc.type === 'hash' || ioc.type === 'md5' || ioc.type === 'sha256') {
        rules.push({
            type: 'YARA',
            title: `Malicious File Hash - ${ioc.value.substring(0, 8)}`,
            format: 'text',
            content: generateYaraContent(ioc, data)
        });
    }

    return rules;
};

const generateSigmaContent = (ioc, data, techniques) => {
    const timestamp = new Date().toISOString().split('T')[0];
    const techTags = techniques.map(t => `attack.${t.id.toLowerCase().replace(/t/, 't')}`).join('\n    - ');

    let selection = '';
    if (ioc.type === 'ip') {
        selection = `DestinationIp: '${ioc.value}'`;
    } else if (ioc.type === 'domain' || ioc.type === 'url') {
        selection = `RemoteUrl: '*${ioc.value}*'`;
    } else {
        selection = `Hashes: '*${ioc.value}*'`;
    }

    return `title: Detection of ${ioc.value}
id: ${Math.random().toString(36).substring(2, 15)}
status: experimental
description: Auto-generated detection rule for IOC identified by Explainable Threat Intel
author: Explainable TIP
date: ${timestamp}
tags:
    - attack.t1583
    ${techTags ? '- ' + techTags : ''}
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        ${selection}
    condition: selection
falsepositives:
    - Unknown
level: high`;
};

const generateYaraContent = (ioc, data) => {
    return `rule Malicious_Hash_${ioc.value.substring(0, 8)} {
    meta:
        description = "Detection for malicious hash identified by Explainable TIP"
        author = "Explainable Threat Intelligence"
        date = "${new Date().toISOString().split('T')[0]}"
    strings:
        $hash = "${ioc.value}"
    condition:
        $hash
}`;
};
