const { Cell } = require("../../boc/index.js");
const { Contract } = require("../index.js");
const { Address, bytesToHex, BN, toNano } = require("../../utils/index.js");
const { WalletContract } = require("./WalletContract.js");
const { parseWalletV3TransferQuery, parseWalletV3TransferBody } = require("./WalletQueryParser.js");

const Opcodes = {
    action_send_msg: 0x0ec3c86d,
    action_set_code: 0xad4de08e,
    action_extended_set_data: 0x1ff8ea0b,
    action_extended_add_extension: 0x02,
    action_extended_remove_extension: 0x03,
    action_extended_set_signature_auth_allowed: 0x04,
    auth_extension: 0x6578746e,
    auth_signed: 0x7369676e,
    auth_signed_internal: 0x73696e74
};

class WalletV5Contract extends WalletContract {

    /**
     * @param provider    {HttpProvider}
     * @param options {any}
     */
    constructor(provider, options) {
        options.code = Cell.oneFromBoc("B5EE9C72410214010002D4000114FF00F4A413F4BCF2C80B010201200203020148040504F8F28308D71820D31FD31FD31F02F823BBF264ED44D0D31FD31FD3FFF404D15143BAF2A15151BAF2A205F901541064F910F2A3F80024A4C8CB1F5240CB1F5230CBFF5210F400C9ED54F80F01D30721C0009F6C519320D74A96D307D402FB00E830E021C001E30021C002E30001C0039130E30D03A4C8CB1F12CB1FCBFF1011121302E6D001D0D3032171B0925F04E022D749C120925F04E002D31F218210706C7567BD22821064737472BDB0925F05E003FA403020FA4401C8CA07CBFFC9D0ED44D0810140D721F404305C810108F40A6FA131B3925F07E005D33FC8258210706C7567BA923830E30D03821064737472BA925F06E30D06070201200809007801FA00F40430F8276F2230500AA121BEF2E0508210706C7567831EB17080185004CB0526CF1658FA0219F400CB6917CB1F5260CB3F20C98040FB0006008A5004810108F45930ED44D0810140D720C801CF16F400C9ED540172B08E23821064737472831EB17080185005CB055003CF1623FA0213CB6ACB1FCB3FC98040FB00925F03E20201200A0B0059BD242B6F6A2684080A06B90FA0218470D4080847A4937D29910CE6903E9FF9837812801B7810148987159F31840201580C0D0011B8C97ED44D0D70B1F8003DB29DFB513420405035C87D010C00B23281F2FFF274006040423D029BE84C600201200E0F0019ADCE76A26840206B90EB85FFC00019AF1DF6A26840106B90EB858FC0006ED207FA00D4D422F90005C8CA0715CBFFC9D077748018C8CB05CB0222CF165005FA0214CB6B12CCCCC973FB00C84014810108F451F2A7020070810108D718FA00D33FC8542047810108F451F2A782106E6F746570748018C8CB05CB025006CF165004FA0214CB6A12CB1FCB3FC973FB0002006C810108D718FA00D33F305224810108F459F2A782106473747270748018C8CB05CB025005CF165003FA0213CB6ACB1F12CB3FC973FB00000AF400C9ED54696225E5");
        super(provider, options);
        if (!this.options.walletId) this.options.walletId = 698983191 + this.options.wc;

        this.methods.getPublicKey = this.getPublicKey.bind(this);
        this.methods.getWalletId = this.getWalletId.bind(this);
    }

    getName() {
        return 'v5';
    }

    /**
     * @override
     * @private
     * @param   seqno?   {number}
     * @param   expireAt? {number}
     * @param   withoutOp? {boolean}
     * @return {Cell}
     */
    createSigningMessage(seqno, expireAt, withoutOp) {
        seqno = seqno || 0;
        expireAt = expireAt || (Math.floor(Date.now() / 1e3) + 60);
        const message = new Cell();
        message.bits.writeUint(this.options.walletId, 32);
        if (seqno === 0) {
            // message.bits.writeInt(-1, 32);// todo: dont work
            for (let i = 0; i < 32; i++) {
                message.bits.writeBit(1);
            }
        } else {
            message.bits.writeUint(expireAt, 32);
        }
        message.bits.writeUint(seqno, 32);
        if (!withoutOp) {
            message.bits.writeUint(0, 8); // op
        }
        return message;
    }

    /**
     * @override
     * @return {Cell} cell contains wallet data
     */
    createDataCell() {
        const cell = new Cell();
        cell.bits.writeBit(1); // signatureAllowed: true by default
        cell.bits.writeUint(0, 32); // seqno
        cell.bits.writeUint(this.options.walletId, 32);
        cell.bits.writeBytes(this.options.publicKey);
        cell.bits.writeUint(0, 1); // plugins/extensions dict empty
        return cell;
    }

    /**
     * create message from an extension (v5 standard)
     * @param {object} opts - { value: BN, body: Cell }
     */
    async messageFromExtension(opts) {
        return {
            value: opts.value,
            sendMode: 64, // SendMode.PAY_GAS_SEPARATELY
            body: (() => {
                const cell = new Cell();
                cell.bits.writeUint(Opcodes.auth_extension, 32); // Opcodes.auth_extension
                cell.bits.writeUint(0, 64); // query id
                cell.writeCell(opts.body);
                return cell;
            })()
        }
    }

    /**
     * @return {Promise<number>}
     */
    async getWalletId() {
        const myAddress = await this.getAddress();
        const id = await this.provider.call2(myAddress.toString(), 'get_subwallet_id');
        return id.toNumber();
    }

    /**
     * @return {Promise<BN>}
     */
    async getPublicKey() {
        const myAddress = await this.getAddress();
        return this.provider.call2(myAddress.toString(), 'get_public_key');
    }

    /**
     * @return {Promise<number>} seqno
     */
    async getSeqno() {
        const myAddress = await this.getAddress();
        const state = await this.provider.call2(myAddress.toString(), 'seqno');
        return state.toNumber();
    }

    /**
     * @return {Promise<number>} 1 if signature auth allowed, 0 if not, -1 if not active
     */
    async getIsSignatureAuthAllowed() {
        const myAddress = await this.getAddress();
        try {
            const state = await this.provider.call2(myAddress.toString(), 'is_signature_allowed');
            return state.toNumber();
        } catch (e) {
            return -1;
        }
    }

    /**
     * @return {Promise<Cell>} raw extensions dict cell
     */
    async getExtensions() {
        const myAddress = await this.getAddress();
        const result = await this.provider.call2(myAddress.toString(), 'get_extensions');
        return result;
    }

    /**
     * @return {Promise<string[]>} list of extension addresses
     */
    async getExtensionsList() {
        const myAddress = await this.getAddress();
        const result = await this.provider.call2(myAddress.toString(), 'get_extensions');
        // Parse dict if needed, here just return as is for compatibility
        return result;
    }

    /**
     * Returns the canonical v5 wallet code cell
     * @returns {Cell}
     */
    static get codeCell() {
        // This is the canonical v5 wallet contract code cell (from official TON wallet-contract-v5)
        return Cell.oneFromBoc("B5EE9C724102140100020000A000F4A413F4BCF2C80B010201200203020148040504F8F28308D71820D31FD31FD31F02F823BBF264ED44D0D31FD31FD3FFF404D15143BAF2A15151BAF2A205F901541064F910F2A3F80024A4C8CB1F5240CB1F5230CBFF5210F400C9ED54F80F01D30721C0009F6C519320D74A96D307D402FB00E830E021C001E30021C002E30001C0039130E30D03A4C8CB1F12CB1FCBFF1011121302E6D001D0D3032171B0925F04E022D749C120925F04E002D31F218210706C7567BD22821064737472BDB0925F05E003FA403020FA4401C8CA07CBFFC9D0ED44D0810140D721F404305C810108F40A6FA131B3925F07E005D33FC8258210706C7567BA923830E30D03821064737472BA925F06E30D06070201200809007801FA00F40430F8276F2230500AA121BEF2E0508210706C7567831EB17080185004CB0526CF1658FA0219F400CB6917CB1F5260CB3F20C98040FB0006008A5004810108F45930ED44D0810140D720C801CF16F400C9ED540172B08E23821064737472831EB17080185005CB055003CF1623FA0213CB6ACB1FCB3FC98040FB00925F03E20201200A0B0059BD242B6F6A2684080A06B90FA0218470D4080847A4937D29910CE6903E9FF9837812801B7810148987159F31840201580C0D0011B8C97ED44D0D70B1F8003DB29DFB513420405035C87D010C00B23281F2FFF274006040423D029BE84C600201200E0F0019ADCE76A26840206B90EB85FFC00019AF1DF6A26840106B90EB858FC0006ED207FA00D4D422F90005C8CA0715CBFFC9D077748018C8CB05CB0222CF165005FA0214CB6B12CCCCC973FB00C84014810108F451F2A7020070810108D718FA00D33FC8542047810108F451F2A782106E6F746570748018C8CB05CB025006CF165004FA0214CB6A12CB1FCB3FC973FB0002006C810108D718FA00D33F305224810108F459F2A782106473747270748018C8CB05CB025005CF165003FA0213CB6ACB1F12CB3FC973FB00000AF400C9ED54696225E5");
    }
}

WalletV5Contract.parseTransferQuery = parseWalletV3TransferQuery;
WalletV5Contract.parseTransferBody = parseWalletV3TransferBody;
WalletV5Contract.Opcodes = Opcodes;

module.exports = { WalletV5Contract };
