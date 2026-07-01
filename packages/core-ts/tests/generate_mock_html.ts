import { writeFileSync } from 'fs';
import { createDelegatedOAuthApp } from '../src/auth/delegated-oauth-app';
import { JWTIssuer } from '../src/oauth/jwt-issuer';

async function generateHtml() {
  const issuer = await JWTIssuer.create('test-server', null);
  const app = createDelegatedOAuthApp({
    serverName: 'test-server',
    flow: 'device_code',
    callbackUrl: 'http://example.com/callback',
    clientId: 'test-client',
    clientSecret: 'test-secret',
    issuer,
    markSetupComplete: async () => {},
  });

  // This is a hacky way to get the HTML, but it's simpler than spinning up the server and intercepting requests
  // We can just construct a mock response object
  let html = '';
  const mockRes = {
    writeHead: () => {},
    end: (body: string) => { html = body; }
  };

  // Access the private method indirectly or just reproduce the HTML structure here
  // For simplicity, since we just want to verify the HTML layout and CSS:
  html = `
  <!DOCTYPE html>
  <html>
  <head>
  <meta charset='utf-8'>
  <title>Authorize test-server</title>
  <style>
  body { font-family: system-ui, sans-serif; background: #0d0d0d; color: #eee;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; }
  .card { background: #181818; padding: 2rem 3rem; border-radius: 12px;
          border: 1px solid #333; max-width: 480px; text-align: center; }
  h1 { margin-top: 0; }
  .code { font-size: 2rem; font-family: ui-monospace, monospace;
           letter-spacing: 0.25em; padding: 1rem 1.5rem; background: #000;
           border-radius: 8px; border: 1px solid #444; margin: 1.5rem 0; }
  a { color: #4ea1ff; }
  .status { margin-top: 1.5rem; color: #888; font-size: 0.9rem; }
  </style>
  </head>
  <body>
  <div class="card">
    <h1>Authorize test-server</h1>
    <p>Visit the URL below and enter this code:</p>
    <div class="code">ABCD-EFGH</div>
    <p><a href="http://example.com/device" target="_blank" rel="noopener noreferrer">http://example.com/device</a></p>
    <p class="status" id="status" role="alert">Waiting for you to approve...</p>
  </div>
  <script>
  // Mock the polling for verification purposes
  setTimeout(() => {
    document.getElementById('status').textContent = 'Authorized! You can close this window.';
  }, 2000);
  </script>
  </body>
  </html>
  `;

  writeFileSync('/tmp/mock_delegated_oauth.html', html);
}

generateHtml().catch(console.error);
