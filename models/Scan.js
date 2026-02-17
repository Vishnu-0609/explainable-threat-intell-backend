import mongoose from 'mongoose';

const scanSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    ioc: {
        type: String,
        required: true,
        index: true
    },
    type: {
        type: String,
        required: true
    },
    risk: {
        type: String,
        enum: ['critical', 'high', 'medium', 'low', 'unknown'],
        required: true
    },
    pattern: {
        type: String,
        default: 'Unknown'
    },
    source: {
        type: String,
        default: 'Heuristic'
    },
    summary: {
        type: String,
        required: true
    },
    techniques: [{
        id: String,
        name: String,
        description: String,
        tactic: String,
        source: String
    }],
    countermeasures: [{
        name: String,
        detail: String
    }]
});

// Optimization for dashboard stats
scanSchema.index({ risk: 1 });
scanSchema.index({ pattern: 1 });

const Scan = mongoose.model('Scan', scanSchema);

export default Scan;
