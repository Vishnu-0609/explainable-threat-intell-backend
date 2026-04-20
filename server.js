import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { analyzeIOC, fetchRecentFeeds } from './services/threatIntel.js';
import { pivotInfrastructure } from './services/pivotService.js';
import { batchGeolocate } from './services/geoService.js';
import mitreService from './services/mitreService.js';
import Scan from './models/Scan.js';
import Rule from './models/Rule.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: process.env.FRONTEND_URL || '*'
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;

if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));
} else {
  console.warn('⚠️ MONGODB_URI not found in .env. Persistence is disabled.');
}

app.get('/api/analyze', async (req, res) => {
  try {
    const { ioc } = req.query;

    if (!ioc) {
      return res.status(400).json({ error: 'IOC parameter is required' });
    }

    const data = await analyzeIOC(ioc);

    // Persist to MongoDB if connected - Deduplication Logic
    if (mongoose.connection.readyState === 1) {
      try {
        const existingScan = await Scan.findOne({ ioc: data.ioc.value });

        const scanData = {
          ioc: data.ioc.value,
          type: data.ioc.type,
          risk: data.ioc.risk_level,
          pattern: data.ioc.attack_pattern || 'Unknown',
          source: data.ioc.ai_source || 'Heuristic',
          summary: data.ioc.explainability,
          techniques: data.techniques || [],
          countermeasures: data.countermeasures || []
        };

        if (existingScan) {
          // Technique Accumulation Logic: Merge new techniques identified during re-analysis
          const existingTechIds = new Set(existingScan.techniques.map(t => t.id));
          const newTechniques = scanData.techniques.filter(t => !existingTechIds.has(t.id));

          const hasChanged =
            existingScan.risk !== scanData.risk ||
            existingScan.pattern !== scanData.pattern ||
            existingScan.summary !== scanData.summary ||
            newTechniques.length > 0;

          if (hasChanged) {
            // Accumulate techniques across runs to provide a more comprehensive threat profile
            const techMap = new Map();
            existingScan.techniques.forEach(t => techMap.set(t.id, t));
            scanData.techniques.forEach(t => techMap.set(t.id, t)); // Latest run overrides for same ID
            scanData.techniques = Array.from(techMap.values());

            Object.assign(existingScan, scanData);
            existingScan.timestamp = Date.now(); // Update the clock on change
            await existingScan.save();
            console.log(`🔄 Scan updated for ${data.ioc.value}. Added ${newTechniques.length} new techniques. Total: ${scanData.techniques.length}`);
          } else {
            console.log(`ℹ️ Analysis results unchanged for ${data.ioc.value}, skipping DB write.`);
          }
        } else {
          // Brand new IOC
          const newScan = new Scan(scanData);
          await newScan.save();
          console.log(`💾 New scan persisted for IOC: ${data.ioc.value}`);
        }
      } catch (dbErr) {
        console.error('Failed to save scan to DB:', dbErr);
      }
    }

    res.json(data);
  } catch (error) {
    console.error('Error in analyze endpoint:', error);
    res.status(500).json({ error: error.message || 'Internal Server Error' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json({
        totalScans: 0,
        riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
        topPatterns: {},
        recentScans: [],
        status: 'disconnected'
      });
    }

    // Fetch stats from MongoDB
    const totalScans = await Scan.countDocuments();

    const riskCounts = await Scan.aggregate([
      { $group: { _id: "$risk", count: { $sum: 1 } } }
    ]);

    const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };
    riskCounts.forEach(r => {
      if (riskDistribution.hasOwnProperty(r._id)) {
        riskDistribution[r._id] = r.count;
      }
    });

    const recentScans = await Scan.find()
      .sort({ timestamp: -1 })
      .limit(10);

    const patternCounts = await Scan.aggregate([
      { $match: { pattern: { $ne: 'Unknown' } } },
      { $group: { _id: "$pattern", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    const topPatterns = {};
    patternCounts.forEach(p => {
      topPatterns[p._id] = p.count;
    });

    res.json({
      totalScans,
      riskDistribution,
      topPatterns,
      recentScans,
      status: 'connected'
    });
  } catch (error) {
    console.error('Error in stats endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch stats from database' });
  }
});

app.get('/api/mitre', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    // Aggregate techniques across all scans
    const scansWithTechniques = await Scan.find({}, { techniques: 1 });

    const techniqueMap = {};

    scansWithTechniques.forEach(scan => {
      scan.techniques.forEach(tech => {
        if (!techniqueMap[tech.id]) {
          techniqueMap[tech.id] = {
            id: tech.id,
            name: tech.name,
            tactic: tech.tactic || 'Unknown',
            description: tech.description,
            detection_count: 0
          };
        }
        techniqueMap[tech.id].detection_count += 1;
      });
    });

    res.json(Object.values(techniqueMap));
  } catch (error) {
    console.error('Error in mitre endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch MITRE data' });
  }
});

app.get('/api/mitre/tactics', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    const scans = await Scan.find({}, { techniques: 1 });
    const tacticStats = {};

    scans.forEach(scan => {
      const seenTacticsInScan = new Set();
      scan.techniques.forEach(tech => {
        if (tech.tactic) {
          const tactics = tech.tactic.split(',').map(t => t.trim());
          tactics.forEach(t => {
            if (!tacticStats[t]) {
              tacticStats[t] = { name: t, detection_count: 0 };
            }
            // Count unique detections per scan or total technique instances?
            // User UI shows "Total Detections" based on tech count.
            // Let's count total detections across all techniques for this tactic.
            tacticStats[t].detection_count += 1;
          });
        }
      });
    });

    res.json(Object.values(tacticStats).sort((a, b) => b.detection_count - a.detection_count));
  } catch (error) {
    console.error('Error in mitre tactics endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch MITRE tactics' });
  }
});

app.get('/api/alerts', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json([]);
    }

    // Fetch scans that have critical or high risk, as these are "alerts"
    const recentScans = await Scan.find({
      risk: { $in: ['critical', 'high', 'medium'] }
    })
      .sort({ timestamp: -1 })
      .limit(50);

    const alerts = recentScans.map(scan => ({
      id: scan._id,
      ioc_id: scan._id,
      behavior: scan.pattern || 'Suspicious Activity Detected',
      risk_level: scan.risk,
      detected_at: scan.timestamp,
      ioc_value: scan.ioc
    }));

    res.json(alerts);
  } catch (error) {
    console.error('Error in alerts endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

app.get('/api/rules', async (req, res) => {
  try {
    const rules = await Rule.find().sort({ timestamp: -1 });
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

app.post('/api/rules', async (req, res) => {
  try {
    const { ioc, type, action, reason } = req.body;
    const rule = new Rule({ ioc, type, action, reason });
    await rule.save();
    res.status(201).json(rule);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create rule' });
  }
});

app.get('/api/feeds', async (req, res) => {
  try {
    const feeds = await fetchRecentFeeds();
    res.json(feeds);
  } catch (error) {
    console.error('Error in feeds endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch threat feeds' });
  }
});

app.get('/api/sources', async (req, res) => {
  try {
    const sources = [
      {
        id: 'virustotal',
        name: 'VirusTotal',
        type: 'reputation_database',
        description: 'Multi-engine malware analysis and domain reputation platform.',
        active: !!process.env.VIRUSTOTAL_API_KEY
      },
      {
        id: 'abuseipdb',
        name: 'AbuseIPDB',
        type: 'reputation_database',
        description: 'IP reputation and abuse reporting database.',
        active: !!process.env.ABUSEIPDB_API_KEY
      },
      {
        id: 'threatfox',
        name: 'ThreatFox',
        type: 'threat_intelligence',
        description: 'Open-source indicator of compromise (IOC) database.',
        active: !!process.env.THREATFOX_API_KEY
      },
      {
        id: 'otx',
        name: 'AlienVault OTX',
        type: 'threat_intelligence',
        description: 'Open threat exchange for sharing community-driven pulses.',
        active: !!process.env.ALIENVAULT_API_KEY
      },
      {
        id: 'malwarebazaar',
        name: 'MalwareBazaar',
        type: 'malware_repository',
        description: 'Project from abuse.ch for sharing malware samples and hashes.',
        active: true // Used in feeds, public API often stable
      },
      {
        id: 'mitre_attack',
        name: 'MITRE ATT&CK',
        type: 'behavioral_analysis',
        description: 'Validated technique mapping using local Enterprise STIX data.',
        active: true // Local dataset is present
      },
      {
        id: 'huggingface',
        name: 'AI Insights (HuggingFace)',
        type: 'ai_analysis',
        description: 'Explainable AI analysis for threat reasoning and countermeasures.',
        active: !!process.env.HUGGINGFACE_API_KEY
      }
    ];

    // Optional: Fetch counts from DB for each source?
    // For now, returning status is what matters for "Data Sources" page.

    res.json(sources);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch data sources' });
  }
});

// ─────────────────────────────────────────────
// Feature 1: Infrastructure Pivoting Engine
// ─────────────────────────────────────────────
app.get('/api/pivot', async (req, res) => {
  try {
    const { ioc, type } = req.query;
    if (!ioc) return res.status(400).json({ error: 'ioc parameter is required' });

    const iocType = type || (ioc.match(/^(\d{1,3}\.){3}\d{1,3}$/) ? 'ip' : 'domain');
    const result = await pivotInfrastructure(ioc, iocType);
    res.json(result);
  } catch (error) {
    console.error('Pivot error:', error);
    res.status(500).json({ error: error.message || 'Pivot failed' });
  }
});

// ─────────────────────────────────────────────
// Feature 2: MITRE ATT&CK Heatmap (Navigator Export)
// ─────────────────────────────────────────────
app.get('/api/mitre/heatmap', async (req, res) => {
  try {
    // Build technique frequency map from all stored scans
    const techniqueMap = {};
    if (mongoose.connection.readyState === 1) {
      const scans = await Scan.find({}, { techniques: 1 });
      scans.forEach(scan => {
        scan.techniques.forEach(tech => {
          if (!tech.id) return;
          const id = tech.id.toUpperCase();
          if (!techniqueMap[id]) {
            techniqueMap[id] = { id, name: tech.name, count: 0, tactic: tech.tactic || 'unknown' };
          }
          techniqueMap[id].count += 1;
        });
      });
    }

    const techniques = Object.values(techniqueMap);
    const maxCount = Math.max(...techniques.map(t => t.count), 1);

    // Generate ATT&CK Navigator layer.json format
    const layer = {
      name: 'Threat Intelligence Platform — Live Detections',
      versions: { attack: '14', navigator: '4.9.1', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `Auto-generated from ${techniques.length} observed techniques across all analyzed IOCs.`,
      filters: { platforms: ['Windows', 'Linux', 'macOS'] },
      sorting: 3,
      layout: { layout: 'side', aggregateFunction: 'max', showID: true, showName: true, showAggregateScores: true },
      hideDisabled: false,
      techniques: techniques.map(t => ({
        techniqueID: t.id,
        tactic: t.tactic?.toLowerCase().replace(/\s+/g, '-') || undefined,
        score: Math.ceil((t.count / maxCount) * 100),  // normalized 0–100
        color: '',
        comment: `Detected ${t.count} time(s) across analyzed IOCs`,
        enabled: true,
        metadata: [],
        showSubtechniques: false
      })),
      gradient: {
        colors: ['#fffcd4', '#f4a582', '#d73027'],
        minValue: 0,
        maxValue: 100
      },
      legendItems: [],
      metadata: [{ name: 'generated', value: new Date().toISOString() }]
    };

    res.json({ layer, stats: { total_techniques: techniques.length, max_detections: maxCount, techniques } });
  } catch (error) {
    console.error('Heatmap error:', error);
    res.status(500).json({ error: error.message || 'Heatmap generation failed' });
  }
});

// ─────────────────────────────────────────────
// Feature 3: IP Geolocation Map
// ─────────────────────────────────────────────
app.get('/api/geo', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.json({ markers: [], stats: { total: 0, countries: 0, critical: 0, high: 0 } });
    }

    // Fetch all IP-type scans from MongoDB
    const ipScans = await Scan.find({ type: 'ip' }, {
      ioc: 1, risk: 1, pattern: 1, summary: 1, timestamp: 1, techniques: 1
    }).sort({ timestamp: -1 }).limit(200);

    if (ipScans.length === 0) {
      return res.json({ markers: [], stats: { total: 0, countries: 0, critical: 0, high: 0 } });
    }

    const uniqueIPs = [...new Set(ipScans.map(s => s.ioc))];

    // Batch geolocate all unique IPs
    const geoResults = await batchGeolocate(uniqueIPs);
    const geoMap = new Map(geoResults.map(g => [g.ip, g]));

    // Merge scan data with geolocation
    const markers = [];
    const processedIPs = new Set();

    for (const scan of ipScans) {
      if (processedIPs.has(scan.ioc)) continue;
      processedIPs.add(scan.ioc);

      const geo = geoMap.get(scan.ioc);
      if (!geo) continue;

      markers.push({
        ip: scan.ioc,
        lat: geo.lat,
        lon: geo.lon,
        country: geo.country,
        countryCode: geo.countryCode,
        city: geo.city,
        region: geo.region,
        isp: geo.isp,
        org: geo.org,
        as: geo.as,
        risk: scan.risk,
        pattern: scan.pattern,
        summary: scan.summary,
        timestamp: scan.timestamp,
        techniqueCount: scan.techniques?.length || 0
      });
    }

    const countries = new Set(markers.map(m => m.country));

    res.json({
      markers,
      stats: {
        total: markers.length,
        countries: countries.size,
        critical: markers.filter(m => m.risk === 'critical').length,
        high: markers.filter(m => m.risk === 'high').length
      }
    });
  } catch (error) {
    console.error('Geo error:', error);
    res.status(500).json({ error: error.message || 'Geolocation lookup failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
