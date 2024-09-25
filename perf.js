const http = require("http");
const { performance } = require("perf_hooks");

const TARGET_URL = "http://127.0.0.1:5469/save-logs";
const CONCURRENT_REQUESTS = 10;
const COOLDOWN_TIME = 1000; // 1 second cooldown between retries
const TEST_DURATION = 60000 * 10; // Run the test for 10 minutes
const MIN_INTERVAL = 10; // Minimum interval between requests (in ms)
const MAX_INTERVAL = 200; // Maximum interval between requests (in ms)

let totalRequests = 0;
let successfulRequests = 0;
let droppedConnections = 0;
let totalLatency = 0;
let startTime = performance.now();
let activeRequests = 0;

function generateRandomPayload() {
    const errors = [
        "rtime is time",
        "connection refused",
        "timeout exceeded",
        "invalid input",
        "resource not found",
        "permission denied",
        "unexpected error occurred"
    ];
    
    return {
        data: JSON.stringify({ error: errors[Math.floor(Math.random() * errors.length)] }),
        dest: `test-${Math.floor(Math.random() * 10)}.log`
    };
}

function getRandomInterval() {
    return Math.floor(Math.random() * (MAX_INTERVAL - MIN_INTERVAL + 1) + MIN_INTERVAL);
}

function makeRequest() {
    if (activeRequests >= CONCURRENT_REQUESTS) {
        return; // Don't exceed concurrent request limit
    }

    activeRequests++;
    const requestStartTime = performance.now();

    const payload = generateRandomPayload();
    const payloadString = JSON.stringify(payload);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payloadString)
        }
    };

    const req = http.request(TARGET_URL, options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        res.on('end', () => {
            const latency = performance.now() - requestStartTime;
            totalRequests++;
            successfulRequests++;
            totalLatency += latency;
            activeRequests--;

            // Schedule next request with a random delay
            setTimeout(makeRequest, getRandomInterval());
        });
    });

    req.on('error', (err) => {
        console.error(`Error: ${err.message}`);
        totalRequests++;
        droppedConnections++;
        activeRequests--;
        setTimeout(makeRequest, COOLDOWN_TIME); // Retry after cooldown
    });

    req.on('timeout', () => {
        console.error('Request timed out');
        totalRequests++;
        droppedConnections++;
        req.destroy();
        activeRequests--;
        setTimeout(makeRequest, getRandomInterval());
    });

    req.write(payloadString);
    req.end();

    req.setTimeout(5000); // 5 seconds timeout
}

// Start the initial batch of concurrent requests
for (let i = 0; i < CONCURRENT_REQUESTS; i++) {
    setTimeout(makeRequest, getRandomInterval());
}

function printStats() {
    const elapsedTime = (performance.now() - startTime) / 1000; // Convert to seconds
    const qps = successfulRequests / elapsedTime;
    const avgLatency = totalLatency / successfulRequests;
    const dropRate = (droppedConnections / totalRequests) * 100;

    console.log(`\nTest Duration: ${elapsedTime.toFixed(2)} seconds`);
    console.log(`Total Requests: ${totalRequests}`);
    console.log(`Successful Requests: ${successfulRequests}`);
    console.log(`Dropped Connections: ${droppedConnections}`);
    console.log(`Drop Rate: ${dropRate.toFixed(2)}%`);
    console.log(`Queries Per Second (QPS): ${qps.toFixed(2)}`);
    console.log(`Average Latency: ${avgLatency.toFixed(2)} ms`);
}

// Set a timer to stop the test after TEST_DURATION
setTimeout(() => {
    console.log('Test duration reached. Stopping test...');
    printStats();
    process.exit();
}, TEST_DURATION);

// Handle script termination
process.on('SIGINT', () => {
    printStats();
    process.exit();
});

console.log(
    `Stress test started. Will run for ${TEST_DURATION / 60000} minutes. Press Ctrl+C to stop early and see results.`,
);