"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const ws_1 = __importDefault(require("ws"));
class DiscordTQR {
    constructor(userToken) {
        this.userToken = userToken;
        this.ws = null;
        this.heartbeatInterval = null;
        this.timeoutMs = 0;
        this.keyPair = null;
        this.fingerprint = null;
        this.user = null;
        this.token = null;
        this.qr = null;
        this.config = {
            remoteAuthGateway: "wss://remote-auth-gateway.discord.gg/?v=2",
            discordRemoteAuthLogin: "https://discord.com/api/v9/users/@me/remote-auth/login",
        };
        if (userToken) {
            this.token = userToken;
        }
    }
    generateKeyPair() {
        const keyPair = crypto_1.default.generateKeyPairSync("rsa", {
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        });
        return keyPair;
    }
    encryptWithPublicKey(publicKey, data) {
        return crypto_1.default.publicEncrypt({
            key: publicKey,
            padding: crypto_1.default.constants.RSA_PKCS1_OAEP_PADDING,
        }, data);
    }
    decryptWithPrivateKey(privateKey, data) {
        return crypto_1.default.privateDecrypt({
            key: privateKey,
            padding: crypto_1.default.constants.RSA_PKCS1_OAEP_PADDING,
        }, data);
    }
    generateProof(decryptedNonce) {
        return crypto_1.default.createHash("sha256").update(decryptedNonce).digest("base64url");
    }
    decodeUserPayload(encryptedPayload) {
        const decoded = Buffer.from(encryptedPayload, "base64url").toString("utf-8");
        const parts = decoded.split(":");
        return {
            id: parts[0],
            discriminator: parseInt(parts[1], 10),
            avatar: parts[2],
            username: parts[3],
        };
    }
    generateQRCode(fingerprint) {
        return `https://discordapp.com/rp/${fingerprint}`;
    }
    sendPacket(op_1) {
        return __awaiter(this, arguments, void 0, function* (op, data = {}) {
            return new Promise((resolve, reject) => {
                this.ws.send(JSON.stringify(Object.assign({ op }, data)), (err) => {
                    if (err)
                        reject(err);
                    else
                        resolve();
                });
            });
        });
    }
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.sendPacket("heartbeat").catch(console.error);
        }, this.timeoutMs);
    }
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }
    getPublicKeyBase64() {
        const publicKeyPem = this.keyPair.publicKey;
        const base64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        return base64;
    }
    getFingerprintFromPublicKey() {
        const publicKeyPem = this.keyPair.publicKey;
        const base64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        const buffer = Buffer.from(base64, "base64");
        return crypto_1.default.createHash("sha256").update(buffer).digest("base64url");
    }
    getPrivateKey() {
        return this.keyPair.privateKey;
    }
    /**
     * Start the remote auth flow and generate a QR code
     * @returns The QR code URL for display
     */
    startRemoteAuth() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                this.ws = new ws_1.default(this.config.remoteAuthGateway);
                this.ws.on("open", () => {
                    console.log("Connected to remote auth gateway");
                });
                this.ws.on("message", (data) => __awaiter(this, void 0, void 0, function* () {
                    try {
                        const packet = JSON.parse(data.toString());
                        yield this.handlePacket(packet, resolve, reject);
                    }
                    catch (e) {
                        reject(e);
                    }
                }));
                this.ws.on("close", () => {
                    this.stopHeartbeat();
                    console.log("WebSocket closed");
                });
                this.ws.on("error", (err) => {
                    reject(err);
                });
            });
        });
    }
    handlePacket(packet, resolve, reject) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (packet.op) {
                case "hello": {
                    const helloPacket = packet;
                    this.timeoutMs = helloPacket.timeout_ms;
                    this.keyPair = this.generateKeyPair();
                    const encodedPublicKey = this.getPublicKeyBase64();
                    yield this.sendPacket("init", { encoded_public_key: encodedPublicKey });
                    break;
                }
                case "nonce_proof": {
                    const noncePacket = packet;
                    const decryptedNonce = this.decryptWithPrivateKey(this.getPrivateKey(), Buffer.from(noncePacket.encrypted_nonce, "base64"));
                    const proof = this.generateProof(decryptedNonce);
                    yield this.sendPacket("nonce_proof", { proof });
                    break;
                }
                case "pending_remote_init": {
                    const initPacket = packet;
                    this.fingerprint = initPacket.fingerprint;
                    const qrUrl = this.generateQRCode(this.fingerprint);
                    this.qr = qrUrl;
                    resolve(qrUrl);
                    break;
                }
                case "pending_ticket": {
                    const ticketPacket = packet;
                    this.user = this.decodeUserPayload(ticketPacket.encrypted_user_payload);
                    break;
                }
                case "pending_login": {
                    const loginPacket = packet;
                    const ticket = loginPacket.ticket;
                    this.stopHeartbeat();
                    const token = yield this.exchangeTicketForToken(ticket);
                    this.token = token;
                    this.ws.close();
                    resolve(token);
                    break;
                }
                case "cancel": {
                    this.stopHeartbeat();
                    this.ws.close();
                    reject(new Error("Login cancelled by user"));
                    break;
                }
                case "heartbeat_ack": {
                    break;
                }
                default:
                    console.log("Unknown packet:", packet);
            }
        });
    }
    exchangeTicketForToken(ticket) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch(this.config.discordRemoteAuthLogin, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ ticket }),
            });
            if (!response.ok) {
                throw new Error(`Failed to exchange ticket: ${response.statusText}`);
            }
            const data = yield response.json();
            return data.encrypted_token;
        });
    }
    /**
     * Get the scanned user info
     * @returns User info from the scanned QR code
     */
    getUser() {
        return this.user;
    }
    /**
     * Get the authentication token
     * @returns The Discord token
     */
    getToken() {
        return this.token || this.userToken;
    }
    /**
     * Close the WebSocket connection
     */
    closeConnection() {
        return __awaiter(this, void 0, void 0, function* () {
            this.stopHeartbeat();
            if (this.ws && this.ws.readyState === ws_1.default.OPEN) {
                this.ws.close();
            }
            this.ws = null;
            this.keyPair = null;
            this.fingerprint = null;
            this.user = null;
        });
    }
}
exports.default = DiscordTQR;
//# sourceMappingURL=index.js.map