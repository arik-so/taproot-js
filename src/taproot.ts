import {bech32m as bech32} from 'bech32';
import bitcoin, {Network} from 'bitcoinjs-lib';
import push_data from 'bitcoinjs-lib/src/push_data.js'
import ops_1 from 'bitcoinjs-lib/src/ops.js';
import {default as debugModule} from 'debug';
import {ECPairFactory, ECPairInterface} from 'ecpair';
import * as ecc from 'tiny-secp256k1';

const debug = debugModule('taproot:taproot');
const ECPair = ECPairFactory(ecc);

export class Taproot {
    // default network
    static network: Network = bitcoin.networks.regtest
    
    public static setNetwork(network: Network){
        Taproot.network = network;
    }
    
    public static calculateOutput(untweakedKey: ECPairInterface, tapTree: TapBranch = null): {address: string, scriptPubKey: Buffer, parityBit: number, tweakedPrivateKey?: Buffer} {
        const untweakedPubkey = untweakedKey.publicKey;
        // even y -> 0, odd y; -> 1
        const parityBit = untweakedPubkey[0] === 2 ? 0 : 1;
        debug("Untweaked pubkey parity: %d, hex: %s", parityBit, untweakedPubkey.toString('hex'));
        const internalPubkey = untweakedPubkey.slice(1, 33);
        debug("Internal (parity-stripped) pubkey: %s", internalPubkey.toString('hex'));
        // empty bytes without a tap tree
        let merkleRoot = Buffer.alloc(0);
        if (tapTree) {
            merkleRoot = tapTree.calculateMerkleRoot();
        }
        debug('Tap tree hash: %s', merkleRoot.toString('hex'));
        const tweakDelta = bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([internalPubkey, merkleRoot]));
        // const tweakDelta = bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([untweakedPubkey, merkleRoot]));
        debug('Tweak integer: %s', tweakDelta.toString('hex'));
        const tweakResult = ecc.xOnlyPointAddTweak(internalPubkey, tweakDelta);

        const untweakedPrivateKey = untweakedKey.privateKey;
        let tweakedPrivateKey: Buffer = null;
        if (untweakedPrivateKey) {
            // Order of the curve (N) - 1
            const N_LESS_1 = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', 'hex');
            // 1 represented as 32 bytes BE
            const ONE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
            const privateKey = untweakedPubkey[0] === 2 ? untweakedPrivateKey : ecc.privateAdd(ecc.privateSub(N_LESS_1, untweakedPrivateKey), ONE);
            tweakedPrivateKey = Buffer.from(ecc.privateAdd(privateKey, tweakDelta));
        }

        if (tweakResult === null) {
            throw new Error('Invalid Tweak');
        }
        const { xOnlyPubkey: tweakedPubkey } = tweakResult;
        // @ts-ignore
        debug("Tweaked pubkey: %s", Buffer.from(tweakedPubkey).toString('hex'));
        
        // scriptPubkey
        const scriptPubKey = Buffer.concat([
            // witness v1, PUSH_DATA 32 bytes
            Buffer.from([0x51, 0x20]),
            // x-only tweaked pubkey
            tweakedPubkey,
        ]);
        const words = bech32.toWords(tweakedPubkey);
        words.unshift(0x01);
        
        const address = bech32.encode(Taproot.network.bech32, words);
        debug('Output script: %s', scriptPubKey.toString('hex'));
        debug('p2tr address: %s', address);
        if (tweakedPrivateKey){
            debug('tweaked privkey: %s', tweakedPrivateKey.toString('hex'));
        }
        
        return {
            address,
            scriptPubKey,
            parityBit,
            tweakedPrivateKey
        };
    }
    
    public static encodeScript(buffer) {
        let num = buffer.length;
        const size = push_data.encodingLength(num);
        const prefix = Buffer.alloc(size, 0);
        // ~6 bit
        if (size === 1) {
            prefix.writeUInt8(num);
            // 8 bit
        } else if (size === 2) {
            prefix.writeUInt8(ops_1.OPS.OP_PUSHDATA1);
            prefix.writeUInt8(num, 1);
            // 16 bit
        } else if (size === 3) {
            prefix.writeUInt8(ops_1.OPS.OP_PUSHDATA);
            prefix.writeUInt16LE(num, 1);
            // 32 bit
        } else {
            prefix.writeUInt8(ops_1.OPS.OP_PUSHDATA4);
            prefix.writeUInt32LE(num, 1);
        }
        return Buffer.concat([prefix, buffer]);
    }
}

export class TapBranch {
    leafA: TapLeaf | TapBranch | null;
    leafB: TapLeaf | TapBranch | null;

    constructor(leafA: TapLeaf | TapBranch | null, leafB: TapLeaf | TapBranch | null = null) {
        this.leafA = leafA;
        this.leafB = leafB;
    }
    
    calculateMerkleRoot(): Buffer {
        let leftHash = Buffer.alloc(0);
        let rightHash = Buffer.alloc(0);
        
        if (this.leafA instanceof TapBranch) {
            leftHash = this.leafA.calculateMerkleRoot();
        }else if(this.leafA instanceof TapLeaf) {
            leftHash = this.leafA.calculateHash();
        }
        
        if (this.leafB instanceof TapBranch) {
            rightHash = this.leafB.calculateMerkleRoot();
        }else if(this.leafB instanceof TapLeaf) {
            rightHash = this.leafB.calculateHash();
        }

        let sortedHashes = [leftHash, rightHash].sort(Buffer.compare);
        
        const sortedPreimage = sortedHashes
        .reduce((p, c) => Buffer.concat([p, c]), Buffer.alloc(0));
        
        if (sortedPreimage.length === 32){
            return sortedPreimage;
        }
        
        const branchHash = bitcoin.crypto.taggedHash('TapBranch', sortedPreimage);
        
        debug('TapBranch: %s -> %s', sortedHashes.map(h => h.toString('hex')).join(', '), branchHash.toString('hex'));
        return branchHash;
    }
    
    calculateControlBlock(parityBit: number, untweakedKey: ECPairInterface, leafId: number): Buffer {
        // if (this.leafA instanceof TapLeaf && this.leafA)
        const siblingHashes = this.findSiblingHashes(leafId);
        if (!(Array.isArray(siblingHashes))) {
            throw new Error('could not find leaf id');
        }
        const controlBlock = Buffer.concat([
            Buffer.alloc(1, parityBit | 192),
            untweakedKey.publicKey.slice(1, 33),
            ...siblingHashes
        ]);
        debug('Control block for leaf %d: %s', leafId, controlBlock.toString('hex'));
        return controlBlock;
    }
    
    private findSiblingHashes(leafId: number, trailingSiblings: Buffer[] = []): Buffer[] | boolean {
        let aHash = null;
        let bHash = null;
        if (this.leafA instanceof TapLeaf){
            aHash = this.leafA.calculateHash();
        } else if (this.leafA instanceof TapBranch) {
            aHash = this.leafA.calculateMerkleRoot();
        }
        if (this.leafB instanceof TapLeaf){
            bHash = this.leafB.calculateHash();
        } else if (this.leafB instanceof TapBranch) {
            bHash = this.leafB.calculateMerkleRoot();
        }
        
        if (this.leafA instanceof TapLeaf && this.leafA.id === leafId){
            if (bHash){
                trailingSiblings.unshift(bHash);
            }
            return trailingSiblings;
        } else if (this.leafB instanceof TapLeaf && this.leafB.id === leafId) {
            if (aHash) {
                trailingSiblings.unshift(aHash);
            }
            return trailingSiblings;
        }
        
        if (!this.leafA && !this.leafB){
            return false;
        }
        
        if (this.leafA instanceof TapBranch){
            if (bHash){
                trailingSiblings.unshift(bHash)
            }
            let aPath = this.leafA.findSiblingHashes(leafId, trailingSiblings);
            if (aPath !== false) {
                return aPath;
            }
        }

        if (this.leafB instanceof TapBranch){
            if (aHash){
                trailingSiblings.unshift(aHash)
            }
            let bPath = this.leafB.findSiblingHashes(leafId, trailingSiblings);
            if (bPath !== false) {
                return bPath;
            }
        }
        
        return false;
    }
}

export class TapLeaf {
    id: number;
    version: number;
    script: Buffer;

    constructor(id: number, script: Buffer) {
        this.id = id;
        this.script = script;
        this.version = 192;
    }
    
    calculateHash(): Buffer {
        let tapLeafPreimage = Buffer.concat([
            Buffer.alloc(1, this.version),
            Taproot.encodeScript(this.script)
        ]);
        const leafHash = bitcoin.crypto.taggedHash('TapLeaf', tapLeafPreimage);
        debug('TapLeaf %d hash: %s', this.id, leafHash.toString('hex'))
        return leafHash;
    }
}