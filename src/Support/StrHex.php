<?php

namespace Anapars\HashtacCrypto\Support;

class StrHex
{
    public static function escape(string $plain): string
    {
        $out = '';
        $len = strlen($plain);
        for ($i = 0; $i < $len; $i++) {
            $out .= '\\x' . bin2hex($plain[$i]);
        }
        return $out;
    }

    /**
     * reverse of escape()
     */
    public static function unescape(string $escaped): string
    {
        return preg_replace_callback(
            '/\\\\x([0-9a-fA-F]{2})|\\\\([0-7]{1,3})/',
            function ($m) {
                if (!empty($m[1])) {
                    return chr(hexdec($m[1]));
                }
                if (!empty($m[2])) {
                    return chr(octdec($m[2]));
                }
                return $m[0];
            },
            $escaped
        );
    }
}
