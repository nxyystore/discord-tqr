"use strict";

import crypto from "crypto";
import WebSocket from "ws";

type DiscordTQRConfig = {
    remoteAuthGateway: string;
    discordRemoteAuthLogin: string;
};

type UserInfo = {
    id: string;
    discriminator: number;
    avatar: string;
    username: string;
};

interface RemoteAuthPacket {
    op: string;
    [key: string]: unknown;
}

class DiscordTQR {
    private ws: WebSocket = null;
    private heartbeatInterval: NodeJS.Timeout = null;
    private timeoutMs: number = 0;
    private keyPair: ReturnType<typeof crypto.generateKeyPairSync> = null;
    private fingerprint: string = null;
    private user: UserInfo = null;
    private token: string = null;

    public qr: string = null;

    public config: DiscordTQRConfig = {
        remoteAuthGateway: "wss://remote-auth-gateway.discord.gg/?v=2",
        discordRemoteAuthLogin: "https://discord.com/api/v9/users/@me/remote-auth/login",
    };

    constructor(public userToken?: string) {
        if (userToken) {
            this.token = userToken;
        }
    }

    private generateKeyPair(): { publicKey: string; privateKey: string } {
        const keyPair = (crypto as any).generateKeyPairSync("rsa", {
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        }) as { publicKey: string; privateKey: string };

        return keyPair;
    }

    private encryptWithPublicKey(publicKey: string, data: Buffer): Buffer {
        return crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            },
            data,
        );
    }

    private decryptWithPrivateKey(privateKey: string, data: Buffer): Buffer {
        return crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            },
            data,
        );
    }

    private generateProof(decryptedNonce: Buffer): string {
        return crypto.createHash("sha256").update(decryptedNonce).digest("base64url");
    }

    private decodeUserPayload(encryptedPayload: string): UserInfo {
        const decoded = Buffer.from(encryptedPayload, "base64url").toString("utf-8");
        const parts = decoded.split(":");
        
        return {
            id: parts[0],
            discriminator: parseInt(parts[1], 10),
            avatar: parts[2],
            username: parts[3],
        };
    }

    private generateQRCode(fingerprint: string): string {
        return `https://discordapp.com/rp/${fingerprint}`;
    }

    private async sendPacket(op: string, data: Record<string, unknown> = {}): Promise<void> {
        return new Promise((resolve, reject) => {
            this.ws.send(JSON.stringify({ op, ...data }), (err: Error) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    private startHeartbeat(): void {
        this.heartbeatInterval = setInterval(() => {
            this.sendPacket("heartbeat").catch(console.error);
        }, this.timeoutMs);
    }

    private stopHeartbeat(): void {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    private getPublicKeyBase64(): string {
        const publicKeyPem = this.keyPair.publicKey as string;
        const base64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        return base64;
    }

    private getFingerprintFromPublicKey(): string {
        const publicKeyPem = this.keyPair.publicKey as string;
        const base64 = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        const buffer = Buffer.from(base64, "base64");
        return crypto.createHash("sha256").update(buffer).digest("base64url");
    }

    private getPrivateKey(): string {
        return this.keyPair.privateKey as string;
    }

    /**
     * Start the remote auth flow and generate a QR code
     * @returns The QR code URL for display
     */
    async startRemoteAuth(): Promise<string> {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.config.remoteAuthGateway);

            this.ws.on("open", () => {
                console.log("Connected to remote auth gateway");
            });

            this.ws.on("message", async (data: WebSocket.Data) => {
                try {
                    const packet: RemoteAuthPacket = JSON.parse(data.toString());
                    await this.handlePacket(packet, resolve, reject);
                } catch (e) {
                    reject(e);
                }
            });

            this.ws.on("close", () => {
                this.stopHeartbeat();
                console.log("WebSocket closed");
            });

            this.ws.on("error", (err: Error) => {
                reject(err);
            });
        });
    }

    private async handlePacket(
        packet: RemoteAuthPacket,
        resolve: (value: string) => void,
        reject: (reason: unknown) => void,
    ): Promise<void> {
        switch (packet.op) {
            case "hello": {
                const helloPacket = packet as unknown as { timeout_ms: number; heartbeat_interval: number };
                this.timeoutMs = helloPacket.timeout_ms;
                
                this.keyPair = this.generateKeyPair();
                
                const encodedPublicKey = this.getPublicKeyBase64();
                await this.sendPacket("init", { encoded_public_key: encodedPublicKey });
                break;
            }

            case "nonce_proof": {
                const noncePacket = packet as unknown as { encrypted_nonce: string };
                const decryptedNonce = this.decryptWithPrivateKey(
                    this.getPrivateKey(),
                    Buffer.from(noncePacket.encrypted_nonce, "base64"),
                );
                const proof = this.generateProof(decryptedNonce);
                await this.sendPacket("nonce_proof", { proof });
                break;
            }

            case "pending_remote_init": {
                const initPacket = packet as unknown as { fingerprint: string };
                this.fingerprint = initPacket.fingerprint;
                const qrUrl = this.generateQRCode(this.fingerprint);
                this.qr = qrUrl;
                resolve(qrUrl);
                break;
            }

            case "pending_ticket": {
                const ticketPacket = packet as unknown as { encrypted_user_payload: string };
                this.user = this.decodeUserPayload(ticketPacket.encrypted_user_payload);
                break;
            }

            case "pending_login": {
                const loginPacket = packet as unknown as { ticket: string };
                const ticket = loginPacket.ticket;
                this.stopHeartbeat();
                
                const token = await this.exchangeTicketForToken(ticket);
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
    }

    private async exchangeTicketForToken(ticket: string): Promise<string> {
        const response = await fetch(this.config.discordRemoteAuthLogin, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ ticket }),
        });

        if (!response.ok) {
            throw new Error(`Failed to exchange ticket: ${response.statusText}`);
        }

        const data = await response.json() as { encrypted_token: string };
        return data.encrypted_token;
    }

    /**
     * Get the scanned user info
     * @returns User info from the scanned QR code
     */
    getUser(): UserInfo | null {
        return this.user;
    }

    /**
     * Get the authentication token
     * @returns The Discord token
     */
    getToken(): string | null {
        return this.token || this.userToken;
    }

    /**
     * Close the WebSocket connection
     */
    async closeConnection(): Promise<void> {
        this.stopHeartbeat();
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.close();
        }
        this.ws = null;
        this.keyPair = null;
        this.fingerprint = null;
        this.user = null;
    }
}

export default DiscordTQR;