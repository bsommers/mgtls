import fs from 'node:fs';
import path from 'node:path';
import type { TLSSocket } from 'node:tls';
import { defineConfig, type Plugin } from 'vite';

const storeDir = process.env.MGTLS_STORE_DIR ?? path.resolve(__dirname, '.mgtls-vite');

const tlsOptions = {
  key: fs.readFileSync(path.join(storeDir, 'certs/vite-srv/key.pem')),
  cert: fs.readFileSync(path.join(storeDir, 'certs/vite-srv/fullchain.pem')),
  ca: fs.readFileSync(path.join(storeDir, 'certs/vite-srv/ca-chain.pem')),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.2' as const,
};

/**
 * Vite plugin that exposes `/__mtls/whoami` returning the verified peer X.509 certificate.
 */
function mgtlsPeerIdentityPlugin(): Plugin {
  return {
    name: 'mgtls-peer-identity',
    configureServer(server) {
      server.middlewares.use('/__mtls/whoami', (req, res) => {
        const socket = req.socket as TLSSocket;
        if (!socket.authorized) {
          res.statusCode = 401;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              authenticated: false,
              error: socket.authorizationError ?? 'Unauthorized client certificate',
            }),
          );
          return;
        }

        const peer = socket.getPeerCertificate(false);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify(
            {
              authenticated: true,
              subject: peer.subject,
              issuer: peer.issuer,
              serialNumber: peer.serialNumber,
              fingerprint256: peer.fingerprint256,
              validFrom: peer.valid_from,
              validTo: peer.valid_to,
              subjectaltname: peer.subjectaltname,
            },
            null,
            2,
          ),
        );
      });
    },
  };
}

export default defineConfig({
  plugins: [mgtlsPeerIdentityPlugin()],
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true,
    https: tlsOptions,
  },
  preview: {
    host: 'localhost',
    port: 4173,
    strictPort: true,
    https: tlsOptions,
  },
});
