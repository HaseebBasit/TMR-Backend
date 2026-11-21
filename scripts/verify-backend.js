const http = require('http');
const app = require('../src/server');

// Run a quick verification test on the Express app
const server = http.createServer(app);

server.listen(5001, () => {
  console.log('[Backend Test] Express server listening on test port 5001');

  // Test /api/health
  http.get('http://localhost:5001/api/health', (res) => {
    let data = '';
    res.on('data', (chunk) => (data += chunk));
    res.on('end', () => {
      try {
        const json = JSON.parse(data);
        if (json.status === 'online') {
          console.log('[PASS] /api/health returned online status');
        } else {
          console.error('[FAIL] Unexpected health status:', json);
          process.exit(1);
        }

        // Test /api/gallery
        http.get('http://localhost:5001/api/gallery', (gRes) => {
          let gData = '';
          gRes.on('data', (chunk) => (gData += chunk));
          gRes.on('end', () => {
            const gJson = JSON.parse(gData);
            if (gJson.success) {
              console.log('[PASS] /api/gallery responded successfully');
              server.close(() => {
                console.log('[ALL BACKEND TESTS PASSED]');
                process.exit(0);
              });
            } else {
              console.error('[FAIL] Gallery route failed');
              process.exit(1);
            }
          });
        });
      } catch (err) {
        console.error('[FAIL] Parse error:', err);
        process.exit(1);
      }
    });
  }).on('error', (err) => {
    console.error('[FAIL] Request failed:', err);
    process.exit(1);
  });
});
