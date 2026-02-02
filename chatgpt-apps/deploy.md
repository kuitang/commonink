# Deploy your app

## Local development

During development you can expose your local server to ChatGPT using a tunnel such as ngrok:

```bash
ngrok http 2091
# https://<subdomain>.ngrok.app/mcp → http://127.0.0.1:2091/mcp
```

Keep the tunnel running while you iterate on your connector. When you change code:

1. Rebuild the component bundle (`npm run build`).
2. Restart your MCP server.
3. Refresh the connector in ChatGPT settings to pull the latest metadata.

## Deployment options

Once you have a working MCP server and component bundle, host them behind a stable HTTPS endpoint. The key requirements are low-latency streaming responses on `/mcp`, dependable TLS, and the ability to surface logs and metrics when something goes wrong.

### Alpic

[Alpic](https://alpic.ai/) maintains a ready-to-deploy Apps SDK starter that bundles an Express MCP server and a React widget workspace.

It includes a one-click deploy button that provisions a hosted endpoint, then you can paste the resulting URL into ChatGPT connector settings to go live.

If you want a reference implementation with HMR for widgets plus a production deployment path, the [Alpic template](https://github.com/alpic-ai/apps-sdk-template) is a fast way to start.

### Vercel

Vercel is another strong fit when you want quick deploys, preview environments for review, and automatic HTTPS.
[They have announced support for ChatGPT Apps hosting](https://vercel.com/changelog/chatgpt-apps-support-on-vercel), so you can ship MCP endpoints alongside your frontend and use Vercel previews to validate connector behavior before promoting to production.

You can use their NextJS [starter template](https://vercel.com/templates/ai/chatgpt-app-with-next-js) to get started.

### Other hosting options

- **Managed containers**: Fly.io, Render, or Railway for quick spin-up and automatic TLS, plus predictable streaming behavior for long-lived requests.
- **Cloud serverless**: Google Cloud Run or Azure Container Apps if you need scale-to-zero, keeping in mind that long cold starts can interrupt streaming HTTP.
- **Kubernetes**: for teams that already run clusters. Front your pods with an ingress controller that supports server-sent events.

Regardless of platform, make sure `/mcp` stays responsive, supports streaming responses, and returns appropriate HTTP status codes for errors.

## Environment configuration

- **Secrets**: store API keys or OAuth client secrets outside your repo. Use platform-specific secret managers and inject them as environment variables.
- **Logging**: log tool-call IDs, request latency, and error payloads. This helps debug user reports once the connector is live.
- **Observability**: monitor CPU, memory, and request counts so you can right-size your deployment.

## Dogfood and rollout

Before launching broadly:

1. **Gate access**: test your connector in developer mode until you are confident in stability.
2. **Run golden prompts**: exercise the discovery prompts you drafted during planning and note precision/recall changes with each release.
3. **Capture artifacts**: record screenshots or screen captures showing the component in MCP Inspector and ChatGPT for reference.

When you are ready for production, update metadata, confirm auth and storage are configured correctly, and publish your app to the ChatGPT Apps Directory.

## Next steps

- Validate tooling and telemetry with the [Test your integration](https://developers.openai.com/apps-sdk/deploy/testing) guide.
- Keep a troubleshooting playbook handy via [Troubleshooting](https://developers.openai.com/apps-sdk/deploy/troubleshooting) so on-call responders can quickly diagnose issues.
- Submit your app to the ChatGPT Apps Directory–learn more in the [Submit your app](https://developers.openai.com/apps-sdk/deploy/submission) guide.
