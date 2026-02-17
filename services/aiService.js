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
    const countermeasures = [
        { name: "Network Isolation", detail: "Isolate affected hosts from the network to prevent lateral movement." },
        { name: "Credential Reset", detail: "Force a password reset for all potentially compromised accounts." }
    ];

    if (tags.some(t => t.includes('rat') || t.includes('trojan') || t.includes('stealer'))) {
        summary = `This ${iocData.ioc.type} exhibits characteristics of a Remote Access Trojan (RAT) or Information Stealer.`;
        reasoning = "The presence of RAT-specific behavioral markers indicates active attempts to exfiltrate sensitive data.";
        pattern = "Data Exfiltration & Remote Access";
        inferred_techniques.push({ id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Inferred from 'stealer/rat' behavioral markers." });
        countermeasures.push({ name: "Endpoint Scans", detail: "Run deep forensic scans for characteristic persistence mechanisms." });
    } else if (tags.some(t => t.includes('cobalt') || t.includes('beacon') || t.includes('c2'))) {
        summary = `The indicator is associated with known Command and Control (C2) infrastructure.`;
        reasoning = "Tactical markers suggest it is part of a post-exploitation framework used for lateral movement.";
        pattern = "Command and Control (C2)";
        inferred_techniques.push({ id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", description: "Standard C2 communication pattern." });
        countermeasures.push({ name: "Block IP/Domain", detail: "Implement immediate firewall blocks at the perimeter." });
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
    "mistralai/Mistral-7B-Instruct-v0.3",
    "meta-llama/Llama-3.2-3B-Instruct",
    "google/gemma-2-2b-it",
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

    const systemPrompt = `You are an Explainable Threat Intelligence (ETI) Engine. 
Your goal is to provide deep, human-readable explanations that clearly describe:
1. WHY the IOC is malicious/suspicious.
2. WHAT attack pattern it belongs to.
3. WHICH MITRE TECHNIQUES and TACTICS are involved.
4. WHAT countermeasures are recommended.

JSON OUTPUT ONLY:
{
    "summary": "Full summary for executive briefing.",
    "reasoning": "Technical 'Why it's malicious' reasoning.",
    "pattern": "Attack pattern name (e.g., Phishing, C2, Ransomware).",
    "inferred_techniques": [
        { "id": "T1XXX", "name": "...", "tactic": "MITRE Tactic Name", "description": "Short reasoning for this technique." }
    ],
    "countermeasures": [
        { "name": "Action Name", "detail": "Specific mitigation detail." }
    ]
}

Available MITRE Tactics: ${mitreService.tactics.map(t => t.name).join(', ')}`;

    const userContent = `Analyze this IOC for the Explainable Intelligence Dashboard:
IOC: ${iocData.ioc.value} (${iocData.ioc.type})
Risk: ${iocData.ioc.risk_level}
Tags: ${JSON.stringify(iocData.behaviors.map(b => b.description))}
Context: ${iocData.ioc.explainability}`;

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
                if (data.summary && data.reasoning && data.countermeasures) {
                    // Validate and enrich techniques using the MITRE dataset
                    if (data.inferred_techniques) {
                        data.inferred_techniques = data.inferred_techniques.map(t => mitreService.validateTechnique(t));
                    }
                    return { ...data, source: `HF (${model.split('/').pop()})` };
                }
            }
        } catch (error) {
            console.warn(`HF Model ${model} failed.`);
        }
    }

    const fallback = generateHeuristicSummary(iocData);
    return { ...fallback, source: 'Heuristic Fallback' };
};
