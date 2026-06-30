import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";

export type EncryptedToken = {
  encryptedToken: string;
  encryptionIv: string;
  encryptionTag: string;
};

export class TokenEncryption {
  private readonly secret =
    process.env.OAUTH_TOKEN_ENCRYPTION_SECRET ?? process.env.SIGNING_KEY_ENCRYPTION_SECRET;

  encrypt(token: string): EncryptedToken {
    this.requireSecret("persist OAuth tokens");
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey(), iv);
    const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);

    return {
      encryptedToken: encrypted.toString("base64url"),
      encryptionIv: iv.toString("base64url"),
      encryptionTag: cipher.getAuthTag().toString("base64url")
    };
  }

  decrypt(encryptedToken: string, iv: string, tag: string): string {
    this.requireSecret("decrypt persisted OAuth tokens");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.encryptionKey(),
      Buffer.from(iv, "base64url")
    );
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(encryptedToken, "base64url")),
      decipher.final()
    ]).toString("utf8");
  }

  private encryptionKey(): Buffer {
    return createHash("sha256").update(this.secret ?? "").digest();
  }

  private requireSecret(action: string): void {
    if (!this.secret) {
      throw new Error(
        `OAUTH_TOKEN_ENCRYPTION_SECRET or SIGNING_KEY_ENCRYPTION_SECRET is required to ${action}`
      );
    }
  }
}
