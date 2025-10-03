const fs = require('fs');
const path = require('path');
const { nanoid } = require('nanoid');
const { createLogger, format, transports } = require('winston');

// --- Logger Setup ---

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
    console.log('Created logs directory:', logsDir);
}

// 🎯 CRITICAL: Define the Winston Logger for all file output
const logger = createLogger({
    level: 'info',
    // 🎯 Use format.json() for Datadog correlation
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.json() // The key for structured logging and trace injection
    ),
    transports: [
        // Log all levels (info, warn, error) to access.log
        new transports.File({
            filename: path.join(logsDir, 'access.log'),
            level: 'info' 
        }),
        // Log only 'error' level to error.log
        new transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error' 
        }),
        // Optional: Console output for local debugging
        new transports.Console() 
    ]
});

// --- Middleware Definitions ---

// Middleware to add request ID (no change needed)
const addRequestId = (req, res, next) => {
    req.reqId = nanoid(8);
    res.setHeader('X-Request-ID', req.reqId);
    next();
};

// 🎯 New: Standard request logger (replaces morgan for access.log)
const requestLogger = (req, res, next) => {
    // Skip health checks
    if (req.url === '/health') {
        return next();
    }
    
    // Log request start/end using Winston
    res.on('finish', () => {
        // Create a structured log object
        const logEntry = {
            method: req.method,
            url: req.originalUrl,
            status: res.statusCode,
            ip: req.ip || req.connection.remoteAddress,
            reqId: req.reqId,
            userId: req.user?.id || 'anonymous',
            message: `Request finished: ${req.method} ${req.originalUrl}`
        };

        // Datadog's dd-trace will automatically inject dd.trace_id and dd.span_id 
        // into this JSON object when it's written by Winston.
        if (res.statusCode >= 400 && res.statusCode < 500) {
            logger.warn(logEntry); // Client error logs
        } else if (res.statusCode >= 500) {
            // Server error logs are now primarily handled by the global error handler
            logger.error(logEntry); 
        } else {
            logger.info(logEntry); // Standard access logs
        }
    });

    next();
};

// 🎯 New: Error Logger (Simplified, as Winston filters levels automatically)
// Note: This middleware is now largely redundant because the global error 
// handler and Winston's level filtering handle error logging. We keep a simple 
// wrapper for clarity.
const errorLogger = (req, res, next) => {
    // If the Winston transport is set to level 'error', it only writes errors to error.log.
    // The global error handler in app.js (handleServerError) will ultimately trigger the logger.error().
    next();
};


// Security logger (Updated to use the Winston logger)
const securityLogger = (req, res, next) => {
    const suspiciousPatterns = [
        /script.*alert/i, /union.*select/i, /drop.*table/i, 
        /<script/i, /javascript:/i
    ];
    
    const url = req.url.toLowerCase();
    const userAgent = (req.get('User-Agent') || '').toLowerCase();
    
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(url) || pattern.test(userAgent)) {
            const logEntry = {
                type: 'SECURITY_ALERT',
                ip: req.ip || req.connection.remoteAddress,
                method: req.method,
                url: req.url,
                userAgent: req.get('User-Agent'),
                reqId: req.reqId,
                userId: req.user?.id || 'anonymous',
                pattern: pattern.source,
                message: 'Suspicious activity detected'
            };
            
            // Log as an error or warn level
            logger.error(logEntry); 
        }
    }
    
    next();
};


module.exports = {
    addRequestId,
    requestLogger,
    errorLogger, // Can be removed later, but kept for minimal app.js changes
    securityLogger,
    logger // 🎯 Export the logger for the global error handler in app.js
};