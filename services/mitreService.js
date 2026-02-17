import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MITRE_FILE_PATH = path.join(__dirname, '..', 'data', 'mitre-attack-enterprise.json');

let techniques = [];
let tactics = [];
let techniqueMap = new Map();
let nameToTechniqueMap = new Map();

/**
 * Loads and parses the MITRE ATT&CK data.
 */
const loadMitreData = () => {
    try {
        if (!fs.existsSync(MITRE_FILE_PATH)) {
            console.error(`MITRE data file not found at ${MITRE_FILE_PATH}`);
            return;
        }

        const rawData = fs.readFileSync(MITRE_FILE_PATH, 'utf-8');
        const bundle = JSON.parse(rawData);

        // Filter for attack-patterns (techniques)
        techniques = bundle.objects.filter(obj => obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated);

        // Filter for x-mitre-tactic
        tactics = bundle.objects.filter(obj => obj.type === 'x-mitre-tactic');

        techniques.forEach(tech => {
            const externalId = tech.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id;
            if (externalId) {
                techniqueMap.set(externalId.toUpperCase(), {
                    id: externalId,
                    name: tech.name,
                    description: tech.description,
                    tactic: tech.kill_chain_phases?.map(p => p.phase_name).join(', ') || 'Unknown',
                    url: tech.external_references?.find(ref => ref.source_name === 'mitre-attack')?.url
                });

                nameToTechniqueMap.set(tech.name.toLowerCase(), externalId);
            }
        });

        console.log(`Loaded ${techniqueMap.size} MITRE techniques and ${tactics.length} tactics.`);
    } catch (error) {
        console.error('Error loading MITRE data:', error);
    }
};

// Initialize the data
loadMitreData();

/**
 * Look up a technique by its ID (e.g., T1003).
 */
export const getTechniqueById = (id) => {
    if (!id) return null;
    return techniqueMap.get(id.toUpperCase()) || null;
};

/**
 * Look up a technique by its name.
 */
export const getTechniqueByName = (name) => {
    if (!name) return null;
    const id = nameToTechniqueMap.get(name.toLowerCase());
    return id ? techniqueMap.get(id) : null;
};

/**
 * Validates and enriches a technique object.
 * If the ID is invalid, it tries to find it by name.
 */
export const validateTechnique = (tech) => {
    if (!tech) return null;

    // Try by ID first
    let validTech = getTechniqueById(tech.id);

    // If not found by ID, try by name
    if (!validTech && tech.name) {
        validTech = getTechniqueByName(tech.name);
    }

    if (validTech) {
        return {
            id: validTech.id,
            name: validTech.name,
            tactic: validTech.tactic,
            description: validTech.description?.split('\n')[0] || tech.description, // Keep it concise
            url: validTech.url,
            validated: true
        };
    }

    return { ...tech, validated: false };
};

export default {
    getTechniqueById,
    getTechniqueByName,
    validateTechnique,
    tactics: tactics.map(t => ({ id: t.external_references[0].external_id, name: t.name }))
};
