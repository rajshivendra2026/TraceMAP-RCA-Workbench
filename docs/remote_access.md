# Remote Access Guide

This document shows four ways to access TraceMAP RCA Workbench from anywhere, from the simplest private option to a more production-style public deployment.

## 1. Tailscale Access

Use this when you want private remote access for yourself or a small team without exposing the app publicly.

### Host setup

1. Install Tailscale on the machine that runs TraceMAP.
2. Log in to the same Tailnet on that machine and on every client device that should access the app.
3. Start the app locally:

```bash
docker compose up --build -d
```

4. Get the host's Tailscale name or IP:

```bash
tailscale ip -4
tailscale status
```

### Access options

- Direct private access:

```text
http://<tailscale-ip>:5050
```

- Or publish the local port with Tailscale Serve:

```bash
sudo tailscale serve --bg 5050
```

Then access the generated Tailscale HTTPS URL shown by:

```bash
tailscale serve status
```

### When to use it

- Best for private analyst access
- No router port forwarding required
- Fastest secure option for a personal or team lab

## 2. Cloudflare Tunnel

Use this when you want a public HTTPS URL without opening inbound ports on your router or host firewall.

### Files

- [`/Users/shivendraraj/Downloads/Tool-2/deploy/cloudflared/config.yml.example`](/Users/shivendraraj/Downloads/Tool-2/deploy/cloudflared/config.yml.example)
- [`/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml`](/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml)

### Setup

1. Create a Cloudflare Tunnel in your Cloudflare account.
2. Create a hostname such as `rca.example.com`.
3. Put the tunnel token into `.env`:

```bash
CLOUDFLARE_TUNNEL_TOKEN=your-token-here
```

4. Start the app and the tunnel profile:

```bash
docker compose -f docker-compose.prod.yml --profile tunnel up --build -d
```

### Result

Cloudflare will route:

```text
https://rca.example.com
```

to the internal app service on port `5050`.

### When to use it

- Public HTTPS access without opening ports
- Good for home-hosted or office-hosted setups
- Easy to combine with Cloudflare Access for login protection

## 3. Caddy HTTPS Reverse Proxy

Use this when you have a public VM or forwarded ports and want a clean HTTPS front end with automatic certificates.

### Files

- [`/Users/shivendraraj/Downloads/Tool-2/deploy/Caddyfile`](/Users/shivendraraj/Downloads/Tool-2/deploy/Caddyfile)
- [`/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml`](/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml)
- [`/Users/shivendraraj/Downloads/Tool-2/.env.example`](/Users/shivendraraj/Downloads/Tool-2/.env.example)

### Setup

1. Copy `.env.example` to `.env`.
2. Set:

```bash
PUBLIC_DOMAIN=rca.example.com
CADDY_EMAIL=admin@example.com
APP_PORT=5050
```

3. Point your DNS `A` or `CNAME` record at the host.
4. Open ports `80` and `443`.
5. Start the stack:

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Result

Caddy will terminate TLS and reverse proxy requests to the TraceMAP app container.

### When to use it

- Best for a VM or server with public DNS
- Automatic HTTPS
- Clean production-style edge layer

## 4. Full Production Compose Stack

This is the deployable bundled setup for a server.

### Stack shape

- `tracemap-rca`: the Flask/Waitress app with `tshark`
- `caddy`: TLS termination and reverse proxy
- `cloudflared` optional profile for tunnel-based exposure

### Start locally

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Start with Cloudflare Tunnel too

```bash
docker compose -f docker-compose.prod.yml --profile tunnel up --build -d
```

### Persisted host directories

- `data/raw_pcaps`
- `data/parsed`
- `data/features`
- `data/models`
- `logs`

Tracked seed knowledge stays in the image and source tree under `data/knowledge_base`.

## Recommendation Matrix

- Tailscale: best private remote access
- Cloudflare Tunnel: best public access without opening ports
- Caddy: best server-style HTTPS setup
- `docker-compose.prod.yml`: best baseline deployment layout

## Security Notes

- Do not expose raw port `5050` to the internet.
- Prefer an auth layer if you publish the app beyond a private network.
- Uploaded PCAPs may contain sensitive telecom or subscriber data, so keep storage and access controls tight.
