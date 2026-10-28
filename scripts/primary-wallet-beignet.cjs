// Disposable JSONL adapter for primary-wallet-regtest.py. Regtest only.
const readline = require("node:readline");
const fs = require("node:fs");
const path = require("node:path");
const { BeignetNode } = require(path.join(
  process.env.BEIGNET_ROOT,
  "dist/cli/beignet-node.js",
));
const output = (value) =>
  process.stdout.write(
    JSON.stringify(value, (_, v) =>
      typeof v === "bigint" ? v.toString() : v,
    ) + "\n",
  );
(async () => {
  const dataDir = process.argv[2];
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const seedPath = path.join(dataDir, "regtest-mnemonic");
  if (!fs.existsSync(seedPath)) {
    if (fs.readdirSync(dataDir).length) {
      throw Error(
        "Existing regtest provider store has no saved mnemonic; use a fresh test directory",
      );
    }
    const { generateMnemonic } = require(path.join(
      process.env.BEIGNET_ROOT,
      "dist/utils/helpers.js",
    ));
    fs.writeFileSync(seedPath, generateMnemonic(), { flag: "wx", mode: 0o600 });
  }
  const electrum = new URL(
    process.env.LFBW_ELECTRUM_URL || "tcp://127.0.0.1:60001",
  );
  const node = await BeignetNode.create({
    network: "regtest",
    dataDir,
    mnemonic: fs.readFileSync(seedPath, "utf8").trim(),
    allowMultipleInstances: true,
    electrumHost: electrum.hostname,
    electrumPort: Number(electrum.port),
    electrumTls: electrum.protocol === "ssl:",
    listenPort: Number(process.argv[3]),
    autoBootstrap: false,
    autoGossipSync: false,
    forwardingEnabled: true,
    jitReceive: { enabled: true, flatFeeSat: 100, feePpm: 1000 },
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  });
  const end = Date.now() + 60000;
  while (!node.getHealth().electrumConnected) {
    if (Date.now() > end) throw Error("Electrum unavailable");
    await new Promise((r) => setTimeout(r, 200));
  }
  const key = node.getInfo().nodeId;
  output({
    ready: true,
    nodeId: key,
    uri: key + "@127.0.0.1:" + process.argv[3],
    address: await node.getNewAddress(),
  });
  for await (const line of readline.createInterface({ input: process.stdin })) {
    let request;
    try {
      request = JSON.parse(line);
      let result;
      switch (request.method) {
        case "sync":
          await node.refreshWallet();
          result = true;
          break;
        case "channels":
          result = node.listChannels();
          break;
        case "balance":
          result = node.getBalance();
          break;
        case "invoice":
          result = node.createInvoice(
            request.amountSats,
            "primary regtest",
            600,
          );
          break;
        case "stop":
          await node.gracefulShutdown();
          output({ id: request.id, result: true });
          process.exit(0);
          break;
        default:
          throw Error("unknown command");
      }
      output({ id: request.id, result });
    } catch (error) {
      output({ id: request?.id, error: String(error.message) });
    }
  }
  await node.gracefulShutdown();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
