import { WsProvider, ApiPromise } from '@polkadot/api';
import { TypeRegistry } from '@polkadot/types';
import { Keyring } from '@polkadot/keyring';
import { Header, Extrinsic } from '@polkadot/types/interfaces';
import { SubmittableExtrinsic } from '@polkadot/api/types';
import { KeyringPair } from '@polkadot/keyring/types';

async function initApi() {
  const provider = new WsProvider('ws://localhost:9944');
  let unsubscribe: () => void;
  await new Promise((resolve) => {
    unsubscribe = provider.on('connected', () => resolve());
  });
  if (unsubscribe) unsubscribe();

  const registry = new TypeRegistry();
  const api = new ApiPromise({
    provider,
    registry,
    types: {
      'Endpoint': {
        _enum: ['Twitter', 'Github', 'Other']
      },
      'PendingVerification': {
        'endpoint': 'Endpoint',
        'url': 'Vec<u8>',
        'submitter': 'AccountId',
        'target': 'AccountId',
      },
      Address: 'LookupSource',
      LookupSource: 'GenericLookupSource',
    }
  });
  return api.isReady;
}

async function main() {
  const api = await initApi();
  const url = 'https://gist.github.com/jnaviask/dc98586540413418520d661474e8a546';
  const target = '5Egwjr3bfKhoPMQHxX3HzgJCHYo8bHNxdXiNHGLaXhjhuoqC';
  const submitterPair = new Keyring({ type: 'sr25519' }).addFromSeed(Buffer.from('12345678901234567890123456789013'));
  const submitter = submitterPair.address;
  const hardcodedSubmitter = '5GmsSR91SsAHTdKuNxGPHjDCzL1CWA4y86YzwciGeE4JsT9z';
  if (submitter !== hardcodedSubmitter) {
    throw new Error(`Invalid submitter address: ${submitter}`);
  }

  // seed submitter with funds
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  const waitTx = (tx: SubmittableExtrinsic<'promise'>, pair: KeyringPair) => {
    return new Promise((resolve, reject) => {
      tx.signAndSend(pair, (result) => {
        console.log('TX status: ' + result.status.toString());
        if (result.status.isReady || result.status.isFuture || result.status.isBroadcast) {
          return;
        } else if (result.status.isInBlock) {
          resolve();
        } else {
          reject();
        }
      });
    })
  };
  await waitTx(api.tx.balances.transfer(submitter, 1000000000), alice);

  // kick off event listener
  const subscription = await api.query.system.events((events) => {
    console.log(`\nReceived ${events.length} events:`);

    // Loop through the Vec<EventRecord>
    events.forEach((record) => {
      // Extract the phase, event and the event types
      const { event, phase } = record;
      const types = event.typeDef;

      // Show what we are busy with
      console.log(`\t${event.section}:${event.method}:: (phase=${phase.toString()})`);
      console.log(`\t\t${event.meta.documentation.toString()}`);

      // Loop through each of the parameters, displaying the type and data
      event.data.forEach((data, index) => {
        console.log(`\t\t\t${types[index].type}: ${data.toString()}`);
      });

      if (event.method === 'VerificationProcessed') {
        process.exit(0);
      }
    });
  });

  // send transaction for verification
  const balance = await api.query.system.account(submitter);
  console.log(`Balance: ${balance.toString()}.`);
  await waitTx(api.tx.worker.createPending(target, 'Twitter', url), submitterPair);
}

main().then(() => {
  console.log('Main function done executing');
})