<?php

namespace Anapars\HashtacCrypto\Contracts;

interface CipherContract
{
    public function encryptArray(array $data): string;
    public function decryptToArray(string $token): ?array;

    public function encryptString(string $plain): string;
    public function decryptString(string $token): ?string;

    public function hexEscape(string $plain): string;
    public function hexUnescape(string $escaped): string;
}
