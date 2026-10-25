/** Copy into Chicory/native-tests only for a separately signed regtest build. */
import 'react-native-url-polyfill/auto';
import React, {useEffect, useState} from 'react';
import {AppRegistry, Platform, ScrollView, Text} from 'react-native';
import {openDeviceWallet} from '../src/embedded/client';
import {installNativeCrypto} from '../src/embedded/random';

const endpoint = 'http://127.0.0.1:31078';
async function run(report: (line: string) => void) {
  installNativeCrypto();
  const config = await (await fetch(endpoint + '/config')).json();
  if (config.network !== 'regtest') throw Error('Regtest only');
  let client: any;
  let settings: any = config.settings;
  const post = (route: string, body: unknown) => fetch(endpoint + route, {
    method: 'POST', body: JSON.stringify(body),
  });
  await post('/ready', {platform: Platform.OS, hermes: !!(globalThis as any).HermesInternal});
  report('Native iOS and Hermes ready');
  for (;;) {
    const command = await (await fetch(endpoint + '/next')).json();
    if (!command.id) continue;
    try {
      let result;
      if (command.operation === 'createWallet') {
        if (client || command.options.network !== 'regtest' ||
          !/^[0-9a-f]{66}@127\.0\.0\.1:\d+$/.test(command.options.primaryUri)) {
          throw Error('Only a fresh disposable local regtest wallet is allowed');
        }
        settings = {network: 'regtest', primaryUri: command.options.primaryUri,
          electrum: command.options.electrum, transport: 'native', relayUrl: '', relayToken: ''};
        client = await openDeviceWallet(settings);
        if ((await client.listWallets()).length !== 0) throw Error('Use a fresh qualification app container');
        result = await client.createWallet(command.options);
      } else if (command.operation === 'startWallet') {
        if (!client) client = await openDeviceWallet(settings);
        client.selectWallet(command.walletId);
        result = await client.startWallet();
      } else if (command.operation === 'close') {
        if (client) await client.close();
        client = undefined;
        result = true;
      } else if (command.operation === 'request') {
        const path = command.body?.path || '';
        if (!/^\/wallets\/[^/]+\/api\/(info|channels|balance|invoice\/(create|decode)|ffor\/epochs)$/.test(path)) {
          throw Error('Unsupported simulator test route');
        }
        result = await client._runtime.request(command.body);
      } else {
        if (!['snapshot', 'refreshWallet', 'quoteReceive', 'receive', 'prepareSend', 'send'].includes(command.operation)) {
          throw Error('Unsupported simulator test operation');
        }
        result = await client[command.operation](...(command.args || []));
      }
      await post('/result', {id: command.id, result});
      report('PASS ' + command.operation);
    } catch (error) {
      await post('/result', {id: command.id, error: String(error)});
      report('FAIL ' + command.operation + ': ' + String(error));
    }
  }
}
function Qualification() {
  const [lines, setLines] = useState<string[]>([]);
  useEffect(() => {
    void run(line => setLines(old => [...old.slice(-15), line])).catch(error => {
      setLines(old => [...old, String(error)]);
      void fetch(endpoint + '/failed', {method: 'POST', body: JSON.stringify({message: String(error)})});
    });
  }, []);
  return <ScrollView contentContainerStyle={{padding: 30, paddingTop: 80}}>
    {lines.map((line, index) => <Text key={index}>{line}</Text>)}
  </ScrollView>;
}
AppRegistry.registerComponent('chicory', () => Qualification);
