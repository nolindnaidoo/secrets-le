// Pre-commit scan target. Every value here is a documented example
// credential or an obvious placeholder — none are live.
export const config = {
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  github: {
    token: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
  },
  // Deliberately not a real vendor prefix: GitHub's push protection rejects
  // recognisable provider keys even in samples, and bypassing that to commit
  // a demo file is the wrong habit. This still trips the extension's
  // generic-credential heuristics, which is what the demo needs.
  service: {
    apiKey: 'svc_live_9f2b7c41d8e6a35b0c4718de9a2f6b83',
  },
  database: {
    url: 'postgres://admin:hunter2@db.internal:5432/app',
    password: 'correct-horse-battery-staple',
  },
  jwt: {
    signingKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.signature',
  },
  api: {
    endpoint: 'https://api.example.com/v1',
    timeoutMs: 30000,
  },
};
