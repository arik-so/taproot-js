import bitcoin from 'bitcoinjs-lib';
import {default as debugModule} from 'debug';
import {ECPairFactory} from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import {TapBranch, TapLeaf, Taproot} from './taproot.js';


const debug = debugModule('taproot:index');
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

(async () => {
    const rootPrivateKey = Buffer.from('abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba', 'hex');
    const ecPair = ECPair.fromPrivateKey(rootPrivateKey);

    const taprootOutput = Taproot.calculateOutput(ecPair);
    // const keySpendOutput = createKeySpendOutput(ecPair.publicKey);
    // console.log(keySpendOutput);

    // tx: 37f2c63247cbcd89b882230ab80b4f0ad3cd9168990fa05a64c06fdc0f2017dd
    // output: 0

    const tx = new bitcoin.Transaction();
    const [txid, vout] = '37f2c63247cbcd89b882230ab80b4f0ad3cd9168990fa05a64c06fdc0f2017dd:0'.split(':');
    tx.version = 2;
    tx.addInput(Buffer.from(txid, 'hex').reverse(), parseInt(vout));
    tx.addOutput(taprootOutput.scriptPubKey, 49.99995e8);
    const sighash = tx.hashForWitnessV1(
        0, // which input
        [taprootOutput.scriptPubKey], // All previous outputs of all inputs
        [50e8], // All previous values of all inputs
        bitcoin.Transaction.SIGHASH_DEFAULT // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
    );
    const signature = Buffer.from(ecc.signSchnorr(sighash, taprootOutput.tweakedPrivateKey, Buffer.alloc(32)));
    tx.ins[0].witness = [signature];
    const txHex = tx.toHex();
    console.log(txHex);
    return;

    Taproot.calculateOutput(ECPair.fromPublicKey(Buffer.from('02d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d', 'hex')));

    

})();

