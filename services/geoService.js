/**
 * Geolocation Service
 * Uses ip-api.com (free, no API key required, 45 req/min)
 * to resolve IP addresses to geographic coordinates.
 */
import axios from 'axios';

// In-memory cache to avoid hammering the free API
const geoCache = new Map();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

/**
 * Geolocate a single IP via ip-api.com
 */
export const geolocateIP = async (ip) => {
    const cached = geoCache.get(ip);
    if (cached && Date.now() - cached.ts < CACHE_TTL) {
        return cached.data;
    }

    try {
        const res = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query`, {
            timeout: 5000
        });

        if (res.data && res.data.status === 'success') {
            const data = {
                ip: res.data.query,
                lat: res.data.lat,
                lon: res.data.lon,
                country: res.data.country,
                countryCode: res.data.countryCode,
                region: res.data.regionName,
                city: res.data.city,
                isp: res.data.isp,
                org: res.data.org,
                as: res.data.as
            };
            geoCache.set(ip, { data, ts: Date.now() });
            return data;
        }
    } catch (e) {
        console.error(`Geo lookup failed for ${ip}:`, e.message);
    }
    return null;
};

/**
 * Batch geolocate IPs using ip-api.com batch endpoint (up to 100 at a time).
 * Much more efficient than individual calls.
 */
export const batchGeolocate = async (ips) => {
    const results = [];
    const toFetch = [];

    // Check cache first
    for (const ip of ips) {
        const cached = geoCache.get(ip);
        if (cached && Date.now() - cached.ts < CACHE_TTL) {
            results.push(cached.data);
        } else {
            toFetch.push(ip);
        }
    }

    // Batch fetch uncached IPs (ip-api.com supports POST batch of up to 100)
    if (toFetch.length > 0) {
        const chunks = [];
        for (let i = 0; i < toFetch.length; i += 100) {
            chunks.push(toFetch.slice(i, i + 100));
        }

        for (const chunk of chunks) {
            try {
                const res = await axios.post(
                    'http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query',
                    chunk.map(ip => ({ query: ip })),
                    { timeout: 10000 }
                );

                if (Array.isArray(res.data)) {
                    for (const entry of res.data) {
                        if (entry.status === 'success') {
                            const data = {
                                ip: entry.query,
                                lat: entry.lat,
                                lon: entry.lon,
                                country: entry.country,
                                countryCode: entry.countryCode,
                                region: entry.regionName,
                                city: entry.city,
                                isp: entry.isp,
                                org: entry.org,
                                as: entry.as
                            };
                            geoCache.set(entry.query, { data, ts: Date.now() });
                            results.push(data);
                        }
                    }
                }
            } catch (e) {
                console.error('Batch geo lookup failed:', e.message);
                // Fallback: try individually for this chunk
                for (const ip of chunk) {
                    const single = await geolocateIP(ip);
                    if (single) results.push(single);
                    // Rate limit: ip-api.com allows 45 req/min for free
                    await new Promise(r => setTimeout(r, 150));
                }
            }
        }
    }

    return results;
};
