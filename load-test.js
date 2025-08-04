// load-test.js - Simple load testing script
const http = require('http');
const { performance } = require('perf_hooks');

class LoadTester {
  constructor(baseUrl, concurrency = 10) {
    this.baseUrl = baseUrl;
    this.concurrency = concurrency;
    this.results = {
      successful: 0,
      failed: 0,
      totalTime: 0,
      minTime: Infinity,
      maxTime: 0,
      errors: []
    };
  }

  async makeRequest(path = '/api/health') {
    return new Promise((resolve) => {
      const startTime = performance.now();
      
      const req = http.get(`${this.baseUrl}${path}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          const endTime = performance.now();
          const responseTime = endTime - startTime;
          
          resolve({
            success: res.statusCode === 200,
            statusCode: res.statusCode,
            responseTime: responseTime,
            data: data
          });
        });
      });

      req.on('error', (error) => {
        const endTime = performance.now();
        resolve({
          success: false,
          error: error.message,
          responseTime: endTime - startTime
        });
      });

      req.setTimeout(10000, () => {
        req.destroy();
        resolve({
          success: false,
          error: 'Timeout',
          responseTime: 10000
        });
      });
    });
  }

  async runConcurrentTest(duration = 30000, path = '/api/health') {
    console.log(`Starting load test:`);
    console.log(`- Concurrency: ${this.concurrency}`);
    console.log(`- Duration: ${duration}ms`);
    console.log(`- Endpoint: ${path}`);
    console.log(`- Target: ${this.baseUrl}`);
    
    const startTime = Date.now();
    const workers = [];

    // Start concurrent workers
    for (let i = 0; i < this.concurrency; i++) {
      const worker = this.worker(duration, path, startTime);
      workers.push(worker);
    }

    // Wait for all workers to complete
    await Promise.all(workers);

    // Calculate and display results
    this.displayResults();
  }

  async worker(duration, path, testStartTime) {
    while (Date.now() - testStartTime < duration) {
      const result = await this.makeRequest(path);
      
      if (result.success) {
        this.results.successful++;
      } else {
        this.results.failed++;
        this.results.errors.push({
          error: result.error || `HTTP ${result.statusCode}`,
          time: new Date().toISOString()
        });
      }

      this.results.totalTime += result.responseTime;
      this.results.minTime = Math.min(this.results.minTime, result.responseTime);
      this.results.maxTime = Math.max(this.results.maxTime, result.responseTime);
    }
  }

  displayResults() {
    const totalRequests = this.results.successful + this.results.failed;
    const avgResponseTime = this.results.totalTime / totalRequests;
    const successRate = (this.results.successful / totalRequests) * 100;

    console.log('\n📊 Load Test Results:');
    console.log('========================');
    console.log(`Total Requests: ${totalRequests}`);
    console.log(`Successful: ${this.results.successful}`);
    console.log(`Failed: ${this.results.failed}`);
    console.log(`Success Rate: ${successRate.toFixed(2)}%`);
    console.log(`\nResponse Times:`);
    console.log(`- Average: ${avgResponseTime.toFixed(2)}ms`);
    console.log(`- Min: ${this.results.minTime.toFixed(2)}ms`);
    console.log(`- Max: ${this.results.maxTime.toFixed(2)}ms`);
    
    if (this.results.errors.length > 0) {
      console.log(`\n❌ Errors (showing first 5):`);
      this.results.errors.slice(0, 5).forEach((error, index) => {
        console.log(`${index + 1}. ${error.error} at ${error.time}`);
      });
    }

    // Performance assessment
    console.log('\n🎯 Performance Assessment:');
    if (successRate > 95 && avgResponseTime < 1000) {
      console.log('✅ Excellent performance');
    } else if (successRate > 90 && avgResponseTime < 2000) {
      console.log('🟡 Good performance');
    } else {
      console.log('🔴 Performance issues detected');
    }
  }
}

// Test different scenarios
async function runTests() {
  const baseUrl = 'http://localhost:3002';
  
  console.log('🧪 Running Load Tests for OTP Server\n');
  
  // Test 1: Health endpoint with low concurrency
  console.log('Test 1: Health Endpoint (10 concurrent users)');
  let tester = new LoadTester(baseUrl, 10);
  await tester.runConcurrentTest(10000, '/api/health');
  
  await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
  
  // Test 2: Health endpoint with medium concurrency
  console.log('\nTest 2: Health Endpoint (25 concurrent users)');
  tester = new LoadTester(baseUrl, 25);
  await tester.runConcurrentTest(10000, '/api/health');
  
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Test 3: Health endpoint with high concurrency
  console.log('\nTest 3: Health Endpoint (50 concurrent users)');
  tester = new LoadTester(baseUrl, 50);
  await tester.runConcurrentTest(10000, '/api/health');
  
  console.log('\n🏁 Load testing complete!');
  console.log('\nNext steps:');
  console.log('1. Try testing with MAC address firewall disabled');
  console.log('2. Test database endpoints with valid data');
  console.log('3. Monitor server resources during tests');
}

// Run the tests
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = LoadTester;