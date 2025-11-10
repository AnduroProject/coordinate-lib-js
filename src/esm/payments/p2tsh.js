import { bitcoin as BITCOIN_NETWORK } from '../networks.js';
import * as bscript from '../script.js';
import {
  isTaptree,
  TAPLEAF_VERSION_MASK,
  stacksEqual,
  NBufferSchemaFactory,
  BufferSchema,
} from '../types.js';
import {
  toHashTree,
  rootHashFromPath,
  findScriptPath,
  tapleafHash,
  LEAF_VERSION_TAPSCRIPT_HASH,
} from './bip360.js';
import * as lazy from './lazy.js';
import { bech32m } from 'bech32';
import { fromBech32 } from '../address.js';
import * as tools from 'uint8array-tools';
import * as v from 'valibot';
const OPS = bscript.OPS;
const TAPROOT_SCRIPT_HASH_WITNESS_VERSION = 0x02;
const ANNEX_PREFIX = 0x50;
/**
 * Creates a Pay-to-Taproot-Script-Hash (P2TSH) payment object.
 *
 * @param a - The payment object containing the necessary data for P2TSH.
 * @param opts - Optional payment options.
 * @returns The P2TSH payment object.
 * @throws {TypeError} If the provided data is invalid or insufficient.
 */
export function p2tsh(a, opts) {
  if (
    !a.address &&
    !a.output &&
    !(a.witness && a.witness.length > 1) &&
    !a.scriptTree &&
    !a.hash
  )
    throw new TypeError('Not enough data for script-path spend');
  opts = Object.assign({ validate: true }, opts || {});
  v.parse(
    v.partial(
      v.object({
        address: v.string(),
        input: NBufferSchemaFactory(0),
        network: v.object({}),
        output: NBufferSchemaFactory(34),
        hash: NBufferSchemaFactory(32), // merkle root hash, the tweak
        signature: v.union([
          NBufferSchemaFactory(64),
          NBufferSchemaFactory(65),
        ]),
        witness: v.array(BufferSchema),
        scriptTree: v.custom(isTaptree, 'Taptree is not of type isTaptree'),
        redeem: v.partial(
          v.object({
            output: BufferSchema, // tapleaf script
            redeemVersion: v.number(), // tapleaf version
            witness: v.array(BufferSchema),
          }),
        ),
        redeemVersion: v.number(),
      }),
    ),
    a,
  );
  const _address = lazy.value(() => {
    return fromBech32(a.address);
  });
  // remove annex if present, ignored by taproot
  const _witness = lazy.value(() => {
    if (!a.witness || !a.witness.length) return;
    if (
      a.witness.length >= 2 &&
      a.witness[a.witness.length - 1][0] === ANNEX_PREFIX
    ) {
      return a.witness.slice(0, -1);
    }
    return a.witness.slice();
  });
  const _hashTree = lazy.value(() => {
    if (a.scriptTree) return toHashTree(a.scriptTree);
    if (a.hash) return { hash: a.hash };
    return;
  });
  const network = a.network || BITCOIN_NETWORK;
  const o = { name: 'p2tsh', network };
  lazy.prop(o, 'address', () => {
    if (!o.pubkey) return;
    const words = bech32m.toWords(o.pubkey);
    words.unshift(TAPROOT_SCRIPT_HASH_WITNESS_VERSION);
    return bech32m.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', () => {
    const hashTree = _hashTree();
    if (hashTree) return hashTree.hash;
    const w = _witness();
    if (w && w.length > 1) {
      const controlBlock = w[w.length - 1];
      const leafVersion = controlBlock[0] & TAPLEAF_VERSION_MASK;
      const script = w[w.length - 2];
      const leafHash = tapleafHash({ output: script, version: leafVersion });
      return rootHashFromPath(controlBlock, leafHash);
    }
    return null;
  });
  lazy.prop(o, 'pubkey', () => {
    if (a.pubkey) return a.pubkey;
    if (a.output) return a.output.slice(2);
    if (a.address) return _address().data;
    // For script-path spends (witness or scriptTree), the pubkey is the merkle root hash
    if ((a.witness && a.witness.length > 1) || a.scriptTree) return o.hash;
    // If hash is provided directly, use it as the pubkey
    if (a.hash) return a.hash;
  });
  lazy.prop(o, 'output', () => {
    if (!o.pubkey) return;
    return bscript.compile([OPS.OP_2, o.pubkey]);
  });
  lazy.prop(o, 'redeemVersion', () => {
    if (a.redeemVersion) return a.redeemVersion;
    if (
      a.redeem &&
      a.redeem.redeemVersion !== undefined &&
      a.redeem.redeemVersion !== null
    ) {
      return a.redeem.redeemVersion;
    }
    return LEAF_VERSION_TAPSCRIPT_HASH;
  });
  lazy.prop(o, 'redeem', () => {
    const witness = _witness(); // witness without annex
    if (!witness || witness.length < 2) return;
    return {
      output: witness[witness.length - 2],
      witness: witness.slice(0, -2),
      redeemVersion: witness[witness.length - 1][0] & TAPLEAF_VERSION_MASK,
    };
  });
  lazy.prop(o, 'signature', () => {
    if (a.signature) return a.signature;
    const witness = _witness(); // witness without annex
    if (!witness || witness.length !== 1) return;
    return witness[0];
  });
  lazy.prop(o, 'witness', () => {
    if (a.witness) return a.witness;
    // Handle script tree case (only when we have a real script tree)
    if (a.scriptTree) {
      const hashTree = _hashTree();
      if (hashTree && a.redeem && a.redeem.output) {
        const leafHash = tapleafHash({
          output: a.redeem.output,
          version: o.redeemVersion,
        });
        const path = findScriptPath(hashTree, leafHash);
        if (!path) return;
        const controlBlock = tools.concat(
          [Uint8Array.from([o.redeemVersion])].concat(path),
        );
        return [a.redeem.output, controlBlock];
      }
    }
    // Handle direct hash case (no script tree)
    if (o.hash && o.redeem && o.redeem.output) {
      // For direct hash case, witness should be [version + redeem.output, signature]
      const witness = [];
      // Add signature if available
      if (o.redeem.witness) {
        witness.push(...o.redeem.witness);
      }
      // Add the redeem script with version prefix
      const versionedRedeemScript = tools.concat([
        Uint8Array.from([o.redeemVersion]),
        o.redeem.output,
      ]);
      witness.push(versionedRedeemScript);
      return witness;
    }
    if (a.signature) return [a.signature];
    return undefined;
  });
  // extended validation
  if (opts.validate) {
    let pubkey = Uint8Array.from([]);
    if (a.address) {
      if (network && network.bech32 !== _address().prefix)
        throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== TAPROOT_SCRIPT_HASH_WITNESS_VERSION)
        throw new TypeError('Invalid address version');
      if (_address().data.length !== 32)
        throw new TypeError('Invalid address data');
      pubkey = _address().data;
    }
    if (a.pubkey) {
      if (pubkey.length > 0 && tools.compare(pubkey, a.pubkey) !== 0)
        throw new TypeError('Pubkey mismatch');
      else pubkey = a.pubkey;
    }
    if (a.output) {
      if (
        a.output.length !== 34 ||
        a.output[0] !== OPS.OP_2 ||
        a.output[1] !== 0x20
      )
        throw new TypeError('Output is invalid');
      if (pubkey.length > 0 && tools.compare(pubkey, a.output.slice(2)) !== 0)
        throw new TypeError('Pubkey mismatch');
      else pubkey = a.output.slice(2);
    }
    const hashTree = _hashTree();
    if (a.hash && hashTree) {
      if (tools.compare(a.hash, hashTree.hash) !== 0)
        throw new TypeError('Hash mismatch');
    }
    // Update the validation logic to handle the case where hashTree might be undefined
    if (a.redeem && a.redeem.output && a.scriptTree && hashTree) {
      const leafHash = tapleafHash({
        output: a.redeem.output,
        version: o.redeemVersion,
      });
      if (!findScriptPath(hashTree, leafHash))
        throw new TypeError('Redeem script not in tree');
    }
    const witness = _witness();
    // compare the provided redeem data with the one computed from witness
    if (a.redeem && o.redeem) {
      if (a.redeem.redeemVersion) {
        if (a.redeem.redeemVersion !== o.redeem.redeemVersion)
          throw new TypeError('Redeem.redeemVersion and witness mismatch');
      }
      if (a.redeem.output) {
        if (bscript.decompile(a.redeem.output).length === 0)
          throw new TypeError('Redeem.output is invalid');
        // output redeem is constructed from the witness
        if (
          o.redeem.output &&
          tools.compare(a.redeem.output, o.redeem.output) !== 0
        )
          throw new TypeError('Redeem.output and witness mismatch');
      }
      if (a.redeem.witness) {
        if (
          o.redeem.witness &&
          !stacksEqual(a.redeem.witness, o.redeem.witness)
        )
          throw new TypeError('Redeem.witness and witness mismatch');
      }
    }
    if (witness && witness.length) {
      // P2TSH is always script-path spending
      const controlBlock = witness[witness.length - 1];
      if (controlBlock.length < 33)
        throw new TypeError(
          `The control-block length is too small. Got ${controlBlock.length}, expected min 33.`,
        );
      if ((controlBlock.length - 33) % 32 !== 0)
        throw new TypeError(
          `The control-block length of ${controlBlock.length} is incorrect!`,
        );
      const m = (controlBlock.length - 33) / 32;
      if (m > 128)
        throw new TypeError(
          `The script path is too long. Got ${m}, expected max 128.`,
        );
      const leafVersion = controlBlock[0] & TAPLEAF_VERSION_MASK;
      const script = witness[witness.length - 2];
      const leafHash = tapleafHash({ output: script, version: leafVersion });
      const hash = rootHashFromPath(controlBlock, leafHash);
      // Validate that the computed hash matches the expected merkle root
      if (pubkey.length && tools.compare(pubkey, hash) !== 0)
        throw new TypeError('Merkle root mismatch for p2tsh witness');
    }
  }
  return Object.assign(o, a);
}
