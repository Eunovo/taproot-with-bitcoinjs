import {
    initEccLib,
    networks,
    script,
    Signer,
    opcodes,
    payments,
    crypto,
    Psbt
} from "bitcoinjs-lib";
import { broadcast, waitUntilUTXO } from "./blockstream_utils";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface } from 'ecpair';
import { Taptree } from "bitcoinjs-lib/src/types";

const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);

console.log(`Running "Pay to Pubkey with taproot example"`);

const network = networks.testnet;
const keypair = ECPair.fromPrivateKey(
    Buffer.from("0cb1c95b2814d998fe83ccf3485ac59e9d30222469b8d7969325b42ad99fae78", "hex"),
    { network }
);

// Tweak the original keypai
const tweakedSigner = tweakSigner(keypair, { network });
// Generate an address from the tweaked public key
const p2pktr = payments.p2tr({
    pubkey: toXOnly(tweakedSigner.publicKey),
    network
});
const p2pktr_addr = p2pktr.address ?? "";
console.log(`Waiting till UTXO is detected at this Address: ${p2pktr_addr}`);

waitUntilUTXO(p2pktr_addr)
    .then(async (data) => {
        console.log(`Using UTXO ${data[0].txid}:${data[0].vout}`);

        const psbt = new Psbt({ network });
        psbt.addInput({
            hash: data[0].txid,
            index: data[0].vout,
            witnessUtxo: { value: data[0].value, script: p2pktr.output! },
            tapInternalKey: toXOnly(keypair.publicKey)
        });

        psbt.addOutput({
            address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
            value: data[0].value - 50
        });

        psbt.signInput(0, tweakedSigner);
        psbt.finalizeAllInputs();

        const tx = psbt.extractTransaction();
        console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
        const txid = await broadcast(tx.toHex());
        console.log(`Success! Txid is ${txid}`);
    });


// TapTree example
console.log(`Running "Taptree example"`);

// Create a tap tree with two spend paths
// One path should allow spending using secret
// The other path should pay to another pubkey

// Let's create a p2pkh address from our original keypair for testing
const p2pkh = payments.p2pkh({
    pubkey: keypair.publicKey,
    network
});

const secret_bytes = Buffer.from('SECRET');
const hash = crypto.hash160(secret_bytes);
const hash_lock_script = script.compile([
    opcodes.OP_HASH160,
    hash,
    opcodes.OP_EQUALVERIFY,
    Buffer.from(p2pkh.address ?? ''),
    opcodes.OP_CHECKSIG
]);

const scriptTree: Taptree = [
    {
        output: hash_lock_script
    },
    {
        output: p2pkh.output!
    }
];

const script_p2tr = payments.p2tr({
    internalPubkey: toXOnly(keypair.publicKey),
    scriptTree,
    network
});
const script_addr = script_p2tr.address ?? '';

console.log(script_p2tr.witness);

console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);
waitUntilUTXO(script_addr)
    .then(async (data) => {
        console.log(`Trying the hash lock path with UTXO ${data[0].txid}:${data[0].vout}`);

        const psbt = new Psbt({ network });
        psbt.addInput({
            hash: data[0].txid,
            index: data[0].vout,
            witnessUtxo: { value: data[0].value, script: script_p2tr.output! },
            tapLeafScript: [
                {
                    leafVersion: 192,
                    script: hash_lock_script,
                    controlBlock: script_p2tr.witness![0]
                }
            ]
        });

        psbt.addOutput({
            address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
            value: data[0].value - 50
        });

        psbt.signInput(0, keypair);
        psbt.finalizeAllInputs();

        const tx = psbt.extractTransaction();
        console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
        const txid = await broadcast(tx.toHex());
        console.log(`Success! Txid is ${txid}`);
    });

function tweakSigner(signer: Signer, opts: any = {}): Signer {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    let privateKey: Uint8Array | undefined = signer.privateKey!;
    if (!privateKey) {
        throw new Error('Private key is required for tweaking signer!');
    }
    if (signer.publicKey[0] === 3) {
        privateKey = tinysecp.privateNegate(privateKey);
    }

    const tweakedPrivateKey = tinysecp.privateAdd(
        privateKey,
        tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
    );
    if (!tweakedPrivateKey) {
        throw new Error('Invalid tweaked private key!');
    }

    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        network: opts.network,
    });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
    return crypto.taggedHash(
        'TapTweak',
        Buffer.concat(h ? [pubKey, h] : [pubKey]),
    );
}

function toXOnly(pubkey: Buffer): Buffer {
    return pubkey.subarray(1, 33)
}
