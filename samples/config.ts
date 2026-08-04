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
  // Not a real vendor prefix on purpose. GitHub push protection rejects
  // recognisable provider keys even inside samples/ — it does not honour the
  // paths-ignore in .github/secret_scanning.yml, which scopes alerts only.
  // This still trips the extension's generic-credential heuristics.
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
