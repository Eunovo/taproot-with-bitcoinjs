import {
    initEccLib,
    networks,
    script,
    Signer,
    payments,
    crypto,
    Psbt
} from "bitcoinjs-lib";
import { broadcast, waitUntilUTXO } from "./blockstream_utils";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface } from 'ecpair';
import { Taptree } from "bitcoinjs-lib/src/types";
import { witnessStackToScriptWitness } from "./witness_stack_to_script_witness";

const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
const network = networks.testnet;

async function start() {
    const keypair = ECPair.makeRandom({ network });

    await start_p2pktr(keypair);
    await start_taptree(keypair);
}

async function start_p2pktr(keypair: Signer) {
    console.log(`Running "Pay to Pubkey with taproot example"`);
    // Tweak the original keypair
    const tweakedSigner = tweakSigner(keypair, { network });
    // Generate an address from the tweaked public key
    const p2pktr = payments.p2tr({
        pubkey: toXOnly(tweakedSigner.publicKey),
        network
    });
    const p2pktr_addr = p2pktr.address ?? "";
    console.log(`Waiting till UTXO is detected at this Address: ${p2pktr_addr}`);

    const utxos = await waitUntilUTXO(p2pktr_addr)
    console.log(`Using UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const psbt = new Psbt({ network });
    psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: p2pktr.output! },
        tapInternalKey: toXOnly(keypair.publicKey)
    });

    psbt.addOutput({
        address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
        value: utxos[0].value - 150
    });

    psbt.signInput(0, tweakedSigner);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();
    console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    const txid = await broadcast(tx.toHex());
    console.log(`Success! Txid is ${txid}`);
}


async function start_taptree(keypair: Signer) {
    // TapTree example
    console.log(`Running "Taptree example"`);

    // Create a tap tree with two spend paths
    // One path should allow spending using secret
    // The other path should pay to another pubkey

    // Make random key for hash_lock
    const hash_lock_keypair = ECPair.makeRandom({ network });

    const secret_bytes = Buffer.from('SECRET');
    const hash = crypto.hash160(secret_bytes);
    // Construct script to pay to hash_lock_keypair if the correct preimage/secret is provided
    const hash_script_asm = `OP_HASH160 ${hash.toString('hex')} OP_EQUALVERIFY ${toXOnly(hash_lock_keypair.publicKey).toString('hex')} OP_CHECKSIG`;
    const hash_lock_script = script.fromASM(hash_script_asm);

    const p2pk_script_asm = `${toXOnly(keypair.publicKey).toString('hex')} OP_CHECKSIG`;
    const p2pk_script = script.fromASM(p2pk_script_asm);

    const scriptTree: Taptree = [
        {
            output: hash_lock_script
        },
        {
            output: p2pk_script
        }
    ];

    const hash_lock_redeem = {
        output: hash_lock_script,
        redeemVersion: 192,
    };
    const p2pk_redeem = {
        output: p2pk_script,
        redeemVersion: 192
    }

    const script_p2tr = payments.p2tr({
        internalPubkey: toXOnly(keypair.publicKey),
        scriptTree,
        network
    });
    const script_addr = script_p2tr.address ?? '';

    const p2pk_p2tr = payments.p2tr({
        internalPubkey: toXOnly(keypair.publicKey),
        scriptTree,
        redeem: p2pk_redeem,
        network
    });

    const hash_lock_p2tr = payments.p2tr({
        internalPubkey: toXOnly(keypair.publicKey),
        scriptTree,
        redeem: hash_lock_redeem,
        network
    });

    console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);
    let utxos = await waitUntilUTXO(script_addr)
    console.log(`Trying the P2PK path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const p2pk_psbt = new Psbt({ network });
    p2pk_psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: p2pk_p2tr.output! },
        tapLeafScript: [
            {
                leafVersion: p2pk_redeem.redeemVersion,
                script: p2pk_redeem.output,
                controlBlock: p2pk_p2tr.witness![p2pk_p2tr.witness!.length - 1]
            }
        ]
    });

    p2pk_psbt.addOutput({
        address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
        value: utxos[0].value - 150
    });

    p2pk_psbt.signInput(0, keypair);
    p2pk_psbt.finalizeAllInputs();

    let tx = p2pk_psbt.extractTransaction();
    console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    let txid = await broadcast(tx.toHex());
    console.log(`Success! Txid is ${txid}`);

    console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);
    utxos = await waitUntilUTXO(script_addr)
    console.log(`Trying the Hash lock spend path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const tapLeafScript = {
        leafVersion: hash_lock_redeem.redeemVersion,
        script: hash_lock_redeem.output,
        controlBlock: hash_lock_p2tr.witness![hash_lock_p2tr.witness!.length - 1]
    };

    const psbt = new Psbt({ network });
    psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: hash_lock_p2tr.output! },
        tapLeafScript: [
            tapLeafScript
        ]
    });

    psbt.addOutput({
        address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
        value: utxos[0].value - 150
    });

    psbt.signInput(0, hash_lock_keypair);

    // We have to construct our witness script in a custom finalizer

    const customFinalizer = (_inputIndex: number, input: any) => {
        const scriptSolution = [
            input.tapScriptSig[0].signature,
            secret_bytes
        ];
        const witness = scriptSolution
            .concat(tapLeafScript.script)
            .concat(tapLeafScript.controlBlock);

        return {
            finalScriptWitness: witnessStackToScriptWitness(witness)
        }
    }

    psbt.finalizeInput(0, customFinalizer);

    tx = psbt.extractTransaction();
    console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    txid = await broadcast(tx.toHex());
    console.log(`Success! Txid is ${txid}`);

    // We can also spend from this address without using the script tree

    console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);
    utxos = await waitUntilUTXO(script_addr)
    console.log(`Trying the Hash lock spend path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const key_spend_psbt = new Psbt({ network });
    key_spend_psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: script_p2tr.output! },
        tapInternalKey: toXOnly(keypair.publicKey),
        tapMerkleRoot: script_p2tr.hash
    });
    key_spend_psbt.addOutput({
        address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
        value: utxos[0].value - 150
    });
    // We need to create a signer tweaked by script tree's merkle root
    const tweakedSigner = tweakSigner(keypair, { tweakHash: script_p2tr.hash });
    key_spend_psbt.signInput(0, tweakedSigner);
    key_spend_psbt.finalizeAllInputs();

    tx = key_spend_psbt.extractTransaction();
    console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    txid = await broadcast(tx.toHex());
    console.log(`Success! Txid is ${txid}`);
}

start().then(() => process.exit());

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
