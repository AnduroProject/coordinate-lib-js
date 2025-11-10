import { Payment, PaymentOpts } from './index.js';
/**
 * Creates a Pay-to-Taproot-Script-Hash (P2TSH) payment object.
 *
 * @param a - The payment object containing the necessary data for P2TSH.
 * @param opts - Optional payment options.
 * @returns The P2TSH payment object.
 * @throws {TypeError} If the provided data is invalid or insufficient.
 */
export declare function p2tsh(a: Payment, opts?: PaymentOpts): Payment;
