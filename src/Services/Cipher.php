<?php

namespace Anapars\HashtacCrypto\Services;

use Anapars\HashtacCrypto\Contracts\CipherContract;
use Anapars\HashtacCrypto\Support\StrHex;

class Cipher implements CipherContract
{
    public function __construct(
        protected string $secret,
        protected string $cipher = 'AES-256-CBC',
        protected bool   $useHmac = true,
        protected string $hmacAlgo = 'sha256'
    ) {
        if (empty($this->secret)) {
            throw new \RuntimeException('HASHTAC_CRYPTO_KEY (secret) is empty.');
        }
    }

    // ---------- Public API (Array) ----------
    public function encryptArray(array $data): string
    {
        return $this->encryptString(json_encode($data, JSON_UNESCAPED_UNICODE));
    }

    public function decryptToArray(string $token): ?array
    {
        $str = $this->decryptString($token);
        return $str ? json_decode($str, true) : null;
    }

    // ---------- Public API (String) ----------
    public function encryptString(string $plain): string
    {
        $ivLen = openssl_cipher_iv_length($this->cipher);
        $iv = random_bytes($ivLen);

        $cipherText = openssl_encrypt($plain, $this->cipher, $this->secret, OPENSSL_RAW_DATA, $iv);
        if ($cipherText === false) {
            throw new \RuntimeException('openssl_encrypt failed.');
        }

        $payload = $iv . $cipherText;

        if ($this->useHmac) {
            $mac = hash_hmac($this->hmacAlgo, $payload, $this->secret, true);
            $payload .= $mac;
        }

        return $this->base64UrlEncode($payload);
    }

    public function decryptString(string $token): ?string
    {
        $payload = $this->base64UrlDecode($token);
        if ($payload === false) {
            return null;
        }

        $ivLen = openssl_cipher_iv_length($this->cipher);
        if ($ivLen === false || strlen($payload) < $ivLen) {
            return null;
        }

        $macLen = $this->useHmac ? strlen(hash($this->hmacAlgo, '', true)) : 0;

        $iv = substr($payload, 0, $ivLen);
        $cipherText = substr($payload, $ivLen, $macLen ? -$macLen : null);

        if ($this->useHmac) {
            $mac = substr($payload, -$macLen);
            $calcMac = hash_hmac($this->hmacAlgo, substr($payload, 0, -$macLen), $this->secret, true);

            if (!hash_equals($mac, $calcMac)) {
                return null; // tampered
            }
        }

        $plain = openssl_decrypt($cipherText, $this->cipher, $this->secret, OPENSSL_RAW_DATA, $iv);

        return $plain === false ? null : $plain;
    }

    // ---------- Public API (Hex Escape) ----------
    public function hexEscape(string $plain): string
    {
        return StrHex::escape($plain);
    }

    public function hexUnescape(string $escaped): string
    {
        return StrHex::unescape($escaped);
    }

    // ---------- Helpers ----------
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecode(string $data): string|false
    {
        $data = strtr($data, '-_', '+/');
        return base64_decode($data . str_repeat('=', (4 - strlen($data) % 4) % 4), true);
    }
}
