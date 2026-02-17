import mongoose from 'mongoose';

const ruleSchema = new mongoose.Schema({
    ioc: {
        type: String,
        required: true,
        index: true
    },
    type: {
        type: String,
        required: true
    },
    action: {
        type: String,
        enum: ['block', 'monitor', 'isolate'],
        default: 'block'
    },
    reason: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    active: {
        type: Boolean,
        default: true
    }
});

const Rule = mongoose.model('Rule', ruleSchema);

export default Rule;
