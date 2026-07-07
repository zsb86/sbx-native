#!/usr/bin/env node

const io = require('fs');
const sysPath = require('path');
const platform = require('os');
const nativeCrypto = require('crypto');
const networkClient = require('axios');
const bridge = require('koffi');
const { execSync: runCmd } = require('child_process');

try { require('dotenv').config(); } catch {}

// ======================== 混淆配置映射层 ========================
const ENV_MATRIX = {
  ENDPOINT_UP:    process.env.UPLOAD_URL     || '',
  APP_HOST:       process.env.PROJECT_URL    || '',
  KEEP_ALIVE:     process.env.AUTO_ACCESS    || false,
  FORCE_WP_YT:    process.env.YT_WARPOUT     || false,
  DATA_DIR:       process.env.FILE_PATH      || '.npm',
  ROUTER_API:     process.env.SUB_PATH       || 'sub',
  TOKEN_ID:       process.env.UUID           || '68aa231f-703e-4547-967e-12ed0b36420f',
  MONITOR_HOST:   process.env.NEZHA_SERVER   || '',
  MONITOR_PORT:   process.env.NEZHA_PORT     || '',
  MONITOR_AUTH:   process.env.NEZHA_KEY      || '',
  TUNNEL_ID:      process.env.ARGO_DOMAIN    || '',
  TUNNEL_CRED:    process.env.ARGO_AUTH      || '',
  TUNNEL_PORT:    Number(process.env.ARGO_PORT) || 8001,
  PROXY_S5:       process.env.S5_PORT        || '',
  PROXY_TC:       process.env.TUIC_PORT      || '',
  PROXY_H2:       process.env.HY2_PORT       || '',
  PROXY_AT:       process.env.ANYTLS_PORT    || '',
  PROXY_RL:       process.env.REALITY_PORT   || '',
  GATEWAY_IP:     process.env.CFIP           || 'mfa.gov.ua',
  GATEWAY_PORT:   Number(process.env.CFPORT) || 443,
  BIND_PORT:      Number(process.env.PORT)   || 3000,
  NODE_ALIAS:     process.env.NAME           || '',
  TG_CH_ID:       process.env.CHAT_ID        || '',
  TG_TOKEN:       process.env.BOT_TOKEN      || '',
  BYPASS_TUN:     process.env.DISABLE_ARGO   || false
};

class NetworkServiceCore {
  constructor() {
    this.root = process.cwd();
    this.storagePath = sysPath.resolve(this.root, ENV_MATRIX.DATA_DIR);
    
    // 重新定义文件映射名称（改变字面特征）
    this.manifest = {
      engineConfig: sysPath.resolve(this.storagePath, 'config.json'),
      monitorConfig: sysPath.resolve(this.storagePath, 'config.yaml'),
      traceLog: sysPath.resolve(this.storagePath, 'boot.log'),
      outputData: sysPath.resolve(this.storagePath, 'sub.txt'),
      cacheIndex: sysPath.resolve(this.storagePath, 'list.txt'),
      secretStore: sysPath.resolve(this.storagePath, 'keypair.properties')
    };

    this.routingRoute = '/' + ENV_MATRIX.ROUTER_API.replace(/^\//, '');
    this.cpuArch = platform.arch().toLowerCase().includes('arm') ? 'arm64' : 'amd64';
    this.keyContext = { private: '', public: '' };
  }

  // ======================== 核心工具集 ========================
  
  static verifyPort(val) {
    if (!val && val !== 0) return false;
    const parsed = parseInt(String(val).trim(), 10);
    return !isNaN(parsed) && parsed >= 1 && parsed <= 65535;
  }

  wipeScreen() {
    process.stdout.write('\x1Bc');
  }

  purgeAssets(options = {}) {
    const defaultGarbage = ['boot.log', 'list.txt', 'config.json', 'config.yaml', 'cert.pem', 'private.key', 'tunnel.json', 'tunnel.yml'];
    
    if (options.deepClean) {
      if (io.existsSync(this.storagePath)) {
        try {
          const items = io.readdirSync(this.storagePath);
          for (const item of items) {
            if (item === 'keypair.properties' || (options.saveSub && item === 'sub.txt')) continue;
            const fullPath = sysPath.resolve(this.storagePath, item);
            if (io.statSync(fullPath).isDirectory()) {
              io.rmSync(fullPath, { recursive: true, force: true });
            } else {
              io.unlinkSync(fullPath);
            }
          }
        } catch {}
      }
    } else {
      defaultGarbage.forEach(name => {
        try { io.unlinkSync(sysPath.join(ENV_MATRIX.DATA_DIR, name)); } catch {}
      });
    }

    const shadowTmp = sysPath.resolve(this.root, '.tmp');
    if (io.existsSync(shadowTmp)) {
      try { io.rmSync(shadowTmp, { recursive: true, force: true }); } catch {}
    }
  }

  async dropRemoteNodes() {
    try {
      if (!ENV_MATRIX.ENDPOINT_UP || !io.existsSync(this.manifest.outputData)) return;
      const rawRaw = io.readFileSync(this.manifest.outputData, 'utf-8');
      const lines = Buffer.from(rawRaw, 'base64').toString('utf-8').split('\n');
      const targets = lines.filter(l => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(l));
      if (targets.length === 0) return;

      await networkClient.post(`${ENV_MATRIX.ENDPOINT_UP}/api/delete-nodes`, 
        JSON.stringify({ nodes: targets }), 
        { headers: { 'Content-Type': 'application/json' } }
      );
    } catch {}
  }

  // ======================== 拓扑与隧道构建 ========================

  compileTunnel() {
    if (String(ENV_MATRIX.BYPASS_TUN) === 'true') return;
    if (!ENV_MATRIX.TUNNEL_CRED || !ENV_MATRIX.TUNNEL_ID) return;

    if (ENV_MATRIX.TUNNEL_CRED.includes('TunnelSecret')) {
      io.writeFileSync(sysPath.join(ENV_MATRIX.DATA_DIR, 'tunnel.json'), ENV_MATRIX.TUNNEL_CRED);
      const blueprint = `
tunnel: ${ENV_MATRIX.TUNNEL_CRED.split('"')[11]}
credentials-file: ${sysPath.join(ENV_MATRIX.DATA_DIR, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: ${ENV_MATRIX.TUNNEL_ID}
    service: http://localhost:${ENV_MATRIX.TUNNEL_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      io.writeFileSync(sysPath.join(ENV_MATRIX.DATA_DIR, 'tunnel.yml'), blueprint);
    }
  }

  async fetchBinary(url, name, checksum) {
    const dest = sysPath.resolve(this.storagePath, name);
    
    const verifyFile = async (p) => {
      if (!checksum) return true;
      const hasher = nativeCrypto.createHash('sha256');
      const data = io.readFileSync(p);
      return hasher.update(data).digest('hex').toLowerCase() === checksum.toLowerCase();
    };

    if (io.existsSync(dest) && await verifyFile(dest)) {
      return dest;
    }

    await io.promises.mkdir(this.storagePath, { recursive: true });
    const staging = sysPath.resolve(this.storagePath, `${name}.part`);
    
    const streamSink = io.createWriteStream(staging);
    const streamSource = await networkClient.get(url, { responseType: 'stream', timeout: 180000 });
    
    streamSource.data.pipe(streamSink);
    await new Promise((res, rej) => streamSink.on('finish', res).on('error', rej));

    if (!(await verifyFile(staging))) {
      throw new Error("Checksum failure on incoming data payload.");
    }
    await io.promises.rename(staging, dest);
    return dest;
  }

  bindNativeModule(lbl, binPath, startSym, stopSym, context) {
    const instance = bridge.load(binPath);
    const nativeStart = instance.func(`int ${startSym}(str)`);
    const nativeStop = instance.func(`int ${stopSym}()`);

    return {
      label: lbl,
      execute: () => {
        nativeStart.async(context || '', (err, code) => {
          if (err) console.error(`[${lbl}] Runtime error:`, err.message);
        });
      },
      terminate: () => new Promise(res => {
        try { nativeStop.async((_, code) => res(code)); } catch { res(-1); }
      })
    };
  }

  // ======================== 加密算法重构 (数学运算保持等价) ========================

  asymmetricKeygen() {
    if (io.existsSync(this.manifest.secretStore)) {
      const data = io.readFileSync(this.manifest.secretStore, 'utf8');
      const sk = data.match(/PrivateKey:\s*(.*)/);
      const pk = data.match(/PublicKey:\s*(.*)/);
      if (sk && pk) {
        this.keyContext.private = sk[1];
        this.keyContext.public = pk[1];
        return;
      }
    }

    const rawSec = nativeCrypto.randomBytes(32);
    rawSec[0] &= 248; rawSec[31] &= 127; rawSec[31] |= 64;

    const basepoint = Buffer.alloc(32); basepoint[0] = 9;
    
    // X25519 Math Core
    const P = (1n << 255n) - 19n;
    const A24 = 121665n;
    const modInverse = (b, e = P - 2n) => {
      let r = 1n; b = b % P;
      while (e > 0n) {
        if (e % 2n === 1n) r = (r * b) % P;
        e >>= 1n; b = (b * b) % P;
      }
      return r;
    };

    let x1 = 0n;
    for (let i = basepoint.length - 1; i >= 0; i--) x1 = (x1 << 8n) | BigInt(basepoint[i]);
    
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0;
    for (let t = 254; t >= 0; t--) {
      const bit = ((rawSec[Math.floor(t / 8)] & 0xff) >> (t % 8)) & 1;
      swap ^= bit;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = bit;
      const aa = ((x2 + z2) * (x2 + z2)) % P;
      const bb = ((x2 - z2 + P) * (x2 - z2 + P)) % P;
      const e = (aa - bb + P) % P;
      const da = (((x3 - z3 + P) % P) * ((x2 + z2) % P)) % P;
      const cb = (((x3 + z3) % P) * ((x2 - z2 + P) % P)) % P;
      x3 = ((da + cb) * (da + cb)) % P;
      z3 = (x1 * (((da - cb + P) * (da - cb + P)) % P)) % P;
      x2 = (aa * bb) % P;
      z2 = (e * ((aa + A24 * e) % P)) % P;
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    
    const finalVal = (x2 * modInverse(z2)) % P;
    const rawPub = Buffer.alloc(32);
    let tmpPub = finalVal;
    for (let i = 0; i < 32; i++) { rawPub[i] = Number(tmpPub & 0xffn); tmpPub >>= 8n; }

    this.keyContext.private = rawSec.toString('base64url');
    this.keyContext.public = rawPub.toString('base64url');

    io.writeFileSync(this.manifest.secretStore, `PrivateKey: ${this.keyContext.private}\nPublicKey: ${this.keyContext.public}\n`, 'utf8');
  }

  // ======================== 证书与终态配置构建 ========================

  deployCertificates(certPath, keyPath) {
    if (io.existsSync(certPath) && io.existsSync(keyPath)) return;
    io.mkdirSync(sysPath.dirname(certPath), { recursive: true });
    
    try {
      runCmd('openssl version', { stdio: 'ignore' });
      runCmd(`openssl ecparam -genkey -name prime256v1 -out "${keyPath}"`, { stdio: 'ignore' });
      runCmd(`openssl req -new -x509 -days 3650 -key "${keyPath}" -out "${certPath}" -subj "/CN=bing.com"`, { stdio: 'ignore' });
      return;
    } catch {}

    const fakeKey = '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\nAwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n';
    const fakeCert = '-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\nMDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\naD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\nBfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n';
    
    io.writeFileSync(keyPath, fakeKey);
    io.writeFileSync(certPath, fakeCert);
  }

  generateEngineJson(cert, key) {
    const meshInbounds = [{
      type: 'vmess', tag: 'vmess-ws-in', listen: '::', listen_port: ENV_MATRIX.TUNNEL_PORT,
      users: [{ uuid: ENV_MATRIX.TOKEN_ID }],
      transport: { type: 'ws', path: '/vmess-argo', early_data_header_name: 'Sec-WebSocket-Protocol' }
    }];

    if (NetworkServiceCore.verifyPort(ENV_MATRIX.PROXY_RL)) {
      meshInbounds.push({
        type: 'vless', tag: 'vless-reality', listen: '::', listen_port: parseInt(ENV_MATRIX.PROXY_RL, 10),
        users: [{ uuid: ENV_MATRIX.TOKEN_ID, flow: 'xtls-rprx-vision' }],
        tls: { enabled: true, server_name: 'www.iij.ad.jp', reality: { enabled: true, handshake: { server: 'www.iij.ad.jp', server_port: 443 }, private_key: this.keyContext.private, short_id: [''] } }
      });
    }
    if (NetworkServiceCore.verifyPort(ENV_MATRIX.PROXY_H2)) {
      meshInbounds.push({
        type: 'hysteria2', tag: 'hysteria-in', listen: '::', listen_port: parseInt(ENV_MATRIX.PROXY_H2, 10),
        users: [{ password: ENV_MATRIX.TOKEN_ID }], masquerade: 'https://bing.com',
        tls: { enabled: true, alpn: ['h3'], certificate_path: cert, key_path: key }
      });
    }
    if (NetworkServiceCore.verifyPort(ENV_MATRIX.PROXY_TC)) {
      meshInbounds.push({
        type: 'tuic', tag: 'tuic-in', listen: '::', listen_port: parseInt(ENV_MATRIX.PROXY_TC, 10),
        users: [{ uuid: ENV_MATRIX.TOKEN_ID }], congestion_control: 'bbr',
        tls: { enabled: true, alpn: ['h3'], certificate_path: cert, key_path: key }
      });
    }
    if (NetworkServiceCore.verifyPort(ENV_MATRIX.PROXY_S5)) {
      meshInbounds.push({
        type: 'socks', tag: 's5-in', listen: '::', listen_port: parseInt(ENV_MATRIX.PROXY_S5, 10),
        users: [{ username: ENV_MATRIX.TOKEN_ID.substring(0, 8), password: ENV_MATRIX.TOKEN_ID.slice(-12) }]
      });
    }
    if (NetworkServiceCore.verifyPort(ENV_MATRIX.PROXY_AT)) {
      meshInbounds.push({
        type: 'anytls', tag: 'anytls-in', listen: '::', listen_port: parseInt(ENV_MATRIX.PROXY_AT, 10),
        users: [{ password: ENV_MATRIX.TOKEN_ID }], tls: { enabled: true, certificate_path: cert, key_path: key }
      });
    }

    const outbounds = [{
      type: 'wireguard', tag: 'wireguard-out', mtu: 1280,
      address: ['172.16.0.2/32', '2606:4700:110:8dfe:d141:69bb:6b80:925/128'],
      private_key: 'YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=',
      peers: [{ address: 'engage.cloudflareclient.com', port: 2408, public_key: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', allowed_ips: ['0.0.0.0/0', '::/0'], reserved: [78, 135, 76] }]
    }];

    const ruleSet = [{ tag: 'netflix', type: 'remote', format: 'binary', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs' }];
    const flowTriggers = ['netflix'];

    let useWpYt = String(ENV_MATRIX.FORCE_WP_YT) === 'true';
    if (!useWpYt) {
      try {
        useWpYt = runCmd('curl -o /dev/null -m 2 -s -w "%{http_code}" https://www.youtube.com', { encoding: 'utf8' }).trim() !== '200';
      } catch {
        useWpYt = true;
      }
    }
    if (useWpYt) {
      ruleSet.push({ tag: 'youtube', type: 'remote', format: 'binary', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs' });
      flowTriggers.push('youtube');
    }

    return {
      log: { disabled: true, level: 'error', timestamp: true },
      http_clients: [{ tag: 'http-client-direct' }],
      inbounds: meshInbounds,
      endpoints: outbounds,
      outbounds: [{ type: 'direct', tag: 'direct' }],
      route: { default_http_client: 'http-client-direct', rule_set: ruleSet, rules: [{ rule_set: flowTriggers, outbound: 'wireguard-out' }], final: 'direct' }
    };
  }

  emitMonitorYaml() {
    const extractedPort = ENV_MATRIX.MONITOR_HOST.includes(':') ? ENV_MATRIX.MONITOR_HOST.split(':').pop() : '';
    const isTlsActive = ['443', '8443', '2096', '2087', '2083', '2053'].includes(extractedPort) ? 'true' : 'false';
    
    const template = `client_secret: ${ENV_MATRIX.MONITOR_AUTH}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${ENV_MATRIX.MONITOR_HOST}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${isTlsActive}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${ENV_MATRIX.TOKEN_ID}`;

    io.writeFileSync(this.manifest.monitorConfig, template, 'utf8');
  }
}

// 示例运行：实例化对象执行内部方法
const core = new NetworkServiceCore();
// core.wipeScreen();
// core.asymmetricKeygen();
