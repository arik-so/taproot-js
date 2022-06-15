import bitcoin from 'bitcoinjs-lib';
import chai from 'chai';
import {ECPairFactory} from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import {TapBranch, TapLeaf, Taproot} from '../src/taproot.js';

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

describe('Transaction Tests', () => {

    it('should create treeless output and transaction', () => {
        // address: bcrt1pekm6vrlsqnwctfa2scktz59qc7hkn6j3kfjwaes09tydu24yxres39hnp6
        const rootPrivateKey = Buffer.from('abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba', 'hex');
        const ecPair = ECPair.fromPrivateKey(rootPrivateKey);

        const taprootOutput = Taproot.calculateOutput(ecPair);
        console.dir(taprootOutput);

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
    });

    it('should create test vector branch and pubkey', () => {
        // address: bcrt1pyyvzurexyeadnnqp04dtv6yu6a4ee0ymjzxe2caynvu437xv5kxs65fqpm
        const tapLeafA = new TapLeaf(0, Buffer.from('20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac', 'hex'));
        const tapTree = new TapBranch(tapLeafA);

        const untweakedKey = ECPair.fromPublicKey(Buffer.from('0293478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820', 'hex'));
        const output = Taproot.calculateOutput(untweakedKey, tapTree);
        const control0 = tapTree.calculateControlBlock(output.parityBit, untweakedKey, 0);

        chai.assert(output.scriptPubKey.toString('hex') === '5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e');
        chai.assert(control0.toString('hex') === 'c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820');

        console.dir(output);
    });
    
    it('should create test vector tree and pubkey', () => {
        // address: bcrt1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcs24qspv
        const tapLeafA = new TapLeaf(0, Buffer.from('2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac', 'hex'));
        const tapLeafB = new TapLeaf(1, Buffer.from('20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac', 'hex'));
        const tapLeafC = new TapLeaf(2, Buffer.from('20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac', 'hex'));
        const tapTree = new TapBranch(tapLeafA, new TapBranch(tapLeafB, tapLeafC));


        const untweakedKey = ECPair.fromPublicKey(Buffer.from('0355adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d', 'hex'));
        const output = Taproot.calculateOutput(untweakedKey, tapTree);
        const control0 = tapTree.calculateControlBlock(output.parityBit, untweakedKey, 0);
        const control1 = tapTree.calculateControlBlock(output.parityBit, untweakedKey, 1);
        const control2 = tapTree.calculateControlBlock(output.parityBit, untweakedKey, 2);
        
        chai.assert(output.scriptPubKey.toString('hex') === '512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831');
        chai.assert(control0.toString('hex') === 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91');
        chai.assert(control1.toString('hex') === 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d');
        chai.assert(control2.toString('hex') === 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d');
        
        console.dir(output);
    });

    it('should create preimage tapscript', () => {
        // address: bcrt1pkc4whhyja5e0tlk7mp3l5hsy4w0h9q9dynlyuj7azj0fv80l38rqyw4vlk
        const rootPrivateKey = Buffer.from('abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba', 'hex');
        const ecPair = ECPair.fromPrivateKey(rootPrivateKey);
        
        const hashReferencePreimage = Buffer.from('arik', 'utf-8');
        const hashReference = bitcoin.crypto.hash160(hashReferencePreimage);
        console.log('preimage:', hashReferencePreimage.toString('hex'));
        console.log('hash:', hashReference.toString('hex'));
        
        const tapScript = bitcoin.script.fromASM('OP_DUP OP_HASH160 da3ae579ab6e7dbbf607b3096e32b0f15fb33a33 OP_EQUALVERIFY');
        const tapLeaf = new TapLeaf(0, tapScript);
        const tapTree = new TapBranch(tapLeaf);

        const taprootOutput = Taproot.calculateOutput(ecPair, tapTree);
        console.dir(taprootOutput);
        
        const controlBlock = tapTree.calculateControlBlock(taprootOutput.parityBit, ecPair, 0);
        
        // TODO: broadcast tx, mine 100 blocks, get transaction id and vout
        const [txid, vout] = '2f4e594fa98ce73a9db4145abfd70514feec01d7af1c90125354520873a07596:0'.split(':');

        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(txid, 'hex').reverse(), parseInt(vout));
        tx.addOutput(taprootOutput.scriptPubKey, 3.12495e8);
        tx.ins[0].witness = [
            hashReferencePreimage, // inputs
            tapScript,
            controlBlock
        ];
        const txHex = tx.toHex();
        console.log(txHex);
    });

    it('should create OP_TRUE tapscript', () => {
        // address: bcrt1pgwknlc87r9zf0n2mur82ch92aswqwgeej42p34k66n0kd5xmtmjqmj37df
        const rootPrivateKey = Buffer.from('abbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba', 'hex');
        const ecPair = ECPair.fromPrivateKey(rootPrivateKey);

        const tapScript = bitcoin.script.fromASM('OP_TRUE');
        const tapLeaf = new TapLeaf(0, tapScript);
        const tapTree = new TapBranch(tapLeaf);

        const taprootOutput = Taproot.calculateOutput(ecPair, tapTree);
        console.dir(taprootOutput);

        const controlBlock = tapTree.calculateControlBlock(taprootOutput.parityBit, ecPair, 0);

        // TODO: broadcast tx, mine 100 blocks, get transaction id and vout
        const [txid, vout] = '27ee1b6439c52be0089f098872726415dd5f00322b17eecb31253f1b888b8acc:0'.split(':');

        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(txid, 'hex').reverse(), parseInt(vout));
        // tx.addOutput(taprootOutput.scriptPubKey, 24.99995e8);
        tx.addOutput(taprootOutput.scriptPubKey, 6.24995e8);
        tx.ins[0].witness = [
            tapScript,
            controlBlock
        ];
        const txHex = tx.toHex();
        console.log(txHex);
    });

});