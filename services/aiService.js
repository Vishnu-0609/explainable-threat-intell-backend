import { HfInference } from "@huggingface/inference";
import dotenv from 'dotenv';
import mitreService from './mitreService.js';

dotenv.config();

const hf = new HfInference(process.env.HUGGINGFACE_API_KEY || "");

/**
 * Heuristic fallback for when AI is unavailable.
 * Generates a "sophisticated" summary and countermeasures based on available tags.
 */
const generateHeuristicSummary = (iocData) => {
    const tags = iocData.behaviors.map(b => b.description.toLowerCase());
    const isMalicious = iocData.ioc.risk_level === 'critical' || iocData.ioc.risk_level === 'high';

    let summary = "";
    let reasoning = "Heuristic assessment based on cross-referenced behavioral markers and reputation scoring.";
    let pattern = "Broad-spectrum Malicious Activity";
    const inferred_techniques = [];
    const iocVal = iocData.ioc.value;
    const iocT = iocData.ioc.type;
    const blockCmd = iocT === 'ip'
        ? `netsh advfirewall firewall add rule name="Block ${iocVal}" dir=out action=block remoteip=${iocVal}`
        : iocT === 'domain'
            ? `Add-Content "C:\\Windows\\System32\\drivers\\etc\\hosts" "0.0.0.0 ${iocVal}"`
            : `reg delete HKCU\\Software\\suspicious /f`;

    const countermeasures = [
        {
            name: "Network Isolation",
            detail: "Isolate affected hosts from the network to prevent lateral movement.",
            command: `netsh interface set interface "Ethernet" admin=disable`
        },
        {
            name: `Block ${iocT.toUpperCase()} on Firewall`,
            detail: "Block all outbound connections to this indicator immediately.",
            command: blockCmd
        }
    ];

    if (tags.some(t => t.includes('rat') || t.includes('trojan') || t.includes('stealer'))) {
        summary = `This ${iocData.ioc.type} exhibits characteristics of a Remote Access Trojan (RAT) or Information Stealer.`;
        reasoning = "The presence of RAT-specific behavioral markers indicates active attempts to exfiltrate sensitive data.";
        pattern = "Data Exfiltration & Remote Access";
        inferred_techniques.push({ id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Inferred from 'stealer/rat' behavioral markers." });
        countermeasures.push({
            name: "Kill Suspicious Processes",
            detail: "Terminate any processes associated with the malware.",
            command: `Get-Process | Where-Object {$_.Path -like "*temp*" -or $_.Path -like "*appdata*"} | Stop-Process -Force`
        });
    } else if (tags.some(t => t.includes('cobalt') || t.includes('beacon') || t.includes('c2'))) {
        summary = `The indicator is associated with known Command and Control (C2) infrastructure.`;
        reasoning = "Tactical markers suggest it is part of a post-exploitation framework used for lateral movement.";
        pattern = "Command and Control (C2)";
        inferred_techniques.push({ id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", description: "Standard C2 communication pattern." });
        countermeasures.push({
            name: "Block C2 at Perimeter",
            detail: "Implement immediate firewall blocks at the perimeter.",
            command: blockCmd
        });
    }

    return {
        summary,
        reasoning,
        pattern,
        inferred_techniques: inferred_techniques.map(t => mitreService.validateTechnique(t)),
        countermeasures
    };
};

const FALLBACK_MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-1.5B-Instruct",
    "mistralai/Mistral-Nemo-Instruct-2407",
    "microsoft/Phi-3-mini-4k-instruct"
];

/**
 * Analyzes threat data using AI to provide explainability, patterns, and mitigations.
 */
export const analyzeWithAI = async (iocData) => {
    if (!process.env.HUGGINGFACE_API_KEY) {
        const h = generateHeuristicSummary(iocData);
        return { ...h, source: 'Heuristic' };
    }

    const iocType = iocData.ioc.type;
    const iocValue = iocData.ioc.value;

    // Command examples ONLY to guide countermeasure format — NOT classification
    const commandExamples = iocType === 'ip'
        ? `netsh advfirewall firewall add rule name="Block ${iocValue}" dir=out action=block remoteip=${iocValue}\niptables -A OUTPUT -d ${iocValue} -j DROP`
        : iocType === 'domain'
            ? `Add-Content "C:\\Windows\\System32\\drivers\\etc\\hosts" "0.0.0.0 ${iocValue}"\necho "0.0.0.0 ${iocValue}" >> /etc/hosts`
            : `reg delete HKCU\\Software\\malware /f\ntaskkill /F /IM malware.exe`;

    const systemPrompt = `You are an Explainable Threat Intelligence (ETI) Engine and a Security Engineer.

STEP 1 — ANALYSIS (derive from IOC data below, do NOT assume based on IOC type):
- Determine the REAL technical attack pattern from the tags, vendor detections, and behaviors provided.
- Identify MITRE ATT&CK techniques that map to the ACTUAL observed behaviors.
- REQUIRED REASONING STYLE: Your "reasoning" MUST be technical and behavioral. 
- HARD RULE: NEVER mention security vendors, antivirus companies, detection engines, or specific product names (e.g., "Bkav", "VirusTotal", "Microsoft", "CrowdStrike", "Lionic", etc.). 
- HARD RULE: Do NOT use phrases like "multiple vendors", "security engines", or "AV detections". 
- FOCUS: Describe ONLY the technical mechanics and behaviors (how it abuses persistence, how it exfiltrates data, which vulnerabilities it targets). 
- Example Reasoning: "Abuses Windows Management Instrumentation (WMI) to achieve cross-process code injection, effectively evading standard endpoint detection while establishing a persistence mechanism in the system registry."

STEP 2 — COUNTERMEASURES (generate real commands for THIS specific IOC):
- Every countermeasure MUST include a "command" field with an actual executable CLI command.
- Do NOT write policy advice ("enable MFA", "patch systems", "train users").
- Focus on IMMEDIATE containment: blocking, killing processes, removing persistence, isolating hosts.
- Format examples for ${iocType} IOC type:
${commandExamples.split('\n').map(l => '  ' + l).join('\n')}

JSON OUTPUT ONLY — no markdown, no explanation outside the JSON:
{
    "summary": "Concise executive-level threat summary based on technical findings. NO vendors.",
    "reasoning": "Technical behavior explanation. ABSOLUTELY NO mention of vendors or detection counts.",
    "pattern": "The specific attack pattern name (Trojan/Dropper/Ransomware/C2/etc.)",
    "relations": "Known malware families, campaigns, or exploit relationships.",
    "inferred_techniques": [
        { "id": "T1XXX", "name": "Technique Name", "tactic": "MITRE Tactic Name", "description": "Why this technique applies to THIS indicator." }
    ],
    "countermeasures": [
        {
            "name": "Brief action name",
            "detail": "One sentence — why this action stops the threat.",
            "command": "Real, executable CLI command targeting ${iocValue}"
        }
    ]
}

Available MITRE Tactics: ${mitreService.tactics.map(t => t.name).join(', ')}`;

    const userContent = `Analyze this IOC for the Explainable Intelligence Dashboard:
IOC: ${iocData.ioc.value} (${iocData.ioc.type})
Risk: ${iocData.ioc.risk_level}
Tags: ${JSON.stringify(iocData.behaviors.map(b => b.description))}
Context: ${iocData.ioc.explainability}
Extended Context: ${JSON.stringify({
        dns: iocData.details?.last_dns_records,
        certificates: iocData.details?.last_https_certificate,
        whois: iocData.details?.whois,
        associated_cves: iocData.cves?.map(c => ({ id: c.id, description: c.description, severity: c.severity }))
    })}`;

    const messages = [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent }
    ];

    for (const model of FALLBACK_MODELS) {
        try {
            const response = await hf.chatCompletion({
                model: model,
                messages: messages,
                max_tokens: 800,
                temperature: 0.1
            });

            const text = response.choices[0].message.content;
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const data = JSON.parse(jsonMatch[0]);
                if (data.summary && data.reasoning) {
                    // Validate and enrich techniques using the MITRE dataset
                    if (data.inferred_techniques) {
                        data.inferred_techniques = data.inferred_techniques.map(t => mitreService.validateTechnique(t));
                    }
                    return { ...data, source: `HF (${model.split('/').pop()})` };
                }
            }
        } catch (error) {
            console.warn(`HF Model ${model} failed: ${error.message}`);
        }
    }

    const fallback = generateHeuristicSummary(iocData);
    return { ...fallback, source: 'Heuristic Fallback' };
};
