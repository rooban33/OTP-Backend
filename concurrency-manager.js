// Simple Concurrency Management
class ConcurrencyManager {
    constructor(maxConcurrent = 3) {
      this.maxConcurrent = maxConcurrent;
      this.activeRequests = new Set();
      this.queue = [];
    }
  
    processRequest(req, res, next) {
      const requestId = `${Date.now()}-${Math.random()}`;
      const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
      const endpoint = req.path;
      
      // If under limit, process immediately
      if (this.activeRequests.size < this.maxConcurrent) {
        this.activeRequests.add(requestId);
        console.log(`Processing immediately [${clientIP}] ${endpoint} - Active: ${this.activeRequests.size}, Queue: ${this.queue.length}`);
        
        // Wrap response to cleanup when done
        const originalJson = res.json;
        const originalSend = res.send;
        const originalEnd = res.end;
        
        const cleanup = () => {
          if (this.activeRequests.has(requestId)) {
            this.activeRequests.delete(requestId);
            console.log(`Request completed [${clientIP}] ${endpoint} - Active: ${this.activeRequests.size}, Queue: ${this.queue.length}`);
            this.processQueue();
          }
        };
  
        res.json = function(...args) {
          cleanup();
          return originalJson.apply(this, args);
        };
  
        res.send = function(...args) {
          cleanup();
          return originalSend.apply(this, args);
        };
  
        res.end = function(...args) {
          cleanup();
          return originalEnd.apply(this, args);
        };
  
        // Also cleanup on response finish/close events as backup
        res.on('finish', cleanup);
        res.on('close', cleanup);
  
        return next();
      }
  
      // Add to queue
      console.log(`Adding to queue [${clientIP}] ${endpoint} - Active: ${this.activeRequests.size}, Queue: ${this.queue.length + 1}`);
      
      this.queue.push({
        requestId,
        req,
        res,
        next,
        queuedAt: Date.now(),
        clientIP,
        endpoint
      });
  
      // Send immediate queue notification to client
      res.status(202).json({
        success: true,
        message: 'Request queued due to high traffic',
        data: {
          position: this.queue.length,
          estimatedWaitTime: `${this.queue.length * 2-3} seconds`,
          requestId: requestId.split('-')[0], // Shortened ID
          queueStatus: 'waiting'
        }
      });
    }
  
    processQueue() {
      if (this.queue.length === 0 || this.activeRequests.size >= this.maxConcurrent) {
        return;
      }
  
      const { requestId, req, res, next, clientIP, endpoint } = this.queue.shift();
      this.activeRequests.add(requestId);
      
      console.log(`Processing from queue [${clientIP}] ${endpoint} - Active: ${this.activeRequests.size}, Queue: ${this.queue.length}`);
  
      // Create new response object since we already sent queue notification
      const originalReq = req;
      
      // Override res.json and res.send to capture the actual response
      const originalJson = res.json;
      const originalSend = res.send;
      const originalEnd = res.end;
      
      let responseSent = false;
      
      const cleanup = () => {
        if (this.activeRequests.has(requestId)) {
          this.activeRequests.delete(requestId);
          console.log(`Queued request completed [${clientIP}] ${endpoint} - Active: ${this.activeRequests.size}, Queue: ${this.queue.length}`);
          this.processQueue();
        }
      };
  
      // Override response methods to send actual API response
      res.json = function(data) {
        if (!responseSent) {
          responseSent = true;
          cleanup();
          // Send actual response (not queue notification)
          return originalJson.call(this, data);
        }
      };
  
      res.send = function(data) {
        if (!responseSent) {
          responseSent = true;
          cleanup();
          return originalSend.call(this, data);
        }
      };
  
      res.end = function(data) {
        if (!responseSent) {
          responseSent = true;
          cleanup();
          return originalEnd.call(this, data);
        }
      };
  
      // Backup cleanup
      res.on('finish', cleanup);
      res.on('close', cleanup);
  
      next();
    }
  
    getStatus() {
      return {
        active: this.activeRequests.size,
        queued: this.queue.length,
        maxConcurrent: this.maxConcurrent
      };
    }
  }
  
  // Create global instance
  const concurrencyManager = new ConcurrencyManager(3);
  
  // Middleware function
  const concurrencyMiddleware = async (req, res, next) => {
    // Skip concurrency control for health/debug endpoints
    if (req.path === '/api/health' || 
        req.path === '/api/debug/network-info' ||
        req.path.startsWith('/api/admin/')) {
      return next();
    }
  
    return concurrencyManager.processRequest(req, res, next);
  };
  
  // Status endpoint
  const getConcurrencyStatus = (req, res) => {
    res.json({
      success: true,
      data: concurrencyManager.getStatus()
    });
  };
  
  module.exports = { concurrencyMiddleware, getConcurrencyStatus };