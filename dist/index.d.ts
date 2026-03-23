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
declare class DiscordTQR {
    userToken?: string;
    private ws;
    private heartbeatInterval;
    private timeoutMs;
    private keyPair;
    private fingerprint;
    private user;
    private token;
    qr: string;
    config: DiscordTQRConfig;
    constructor(userToken?: string);
    private generateKeyPair;
    private encryptWithPublicKey;
    private decryptWithPrivateKey;
    private generateProof;
    private decodeUserPayload;
    private generateQRCode;
    private sendPacket;
    private startHeartbeat;
    private stopHeartbeat;
    private getPublicKeyBase64;
    private getFingerprintFromPublicKey;
    private getPrivateKey;
    /**
     * Start the remote auth flow and generate a QR code
     * @returns The QR code URL for display
     */
    startRemoteAuth(): Promise<string>;
    private handlePacket;
    private exchangeTicketForToken;
    /**
     * Get the scanned user info
     * @returns User info from the scanned QR code
     */
    getUser(): UserInfo | null;
    /**
     * Get the authentication token
     * @returns The Discord token
     */
    getToken(): string | null;
    /**
     * Close the WebSocket connection
     */
    closeConnection(): Promise<void>;
}
export default DiscordTQR;
