<?php

namespace Anapars\HashtacCrypto\Console;

use Illuminate\Console\Command;
use HashtacCipher;

class HashtacSealUrlCommand extends Command
{
    protected $signature = 'hashtac:seal-url {url}';
    protected $description = 'Encrypt (seal) a URL so you can safely put it in .env';

    public function handle()
    {
        $url = $this->argument('url');
        $sealed = \HashtacCipher::encryptString($url);
        $this->info("Put this in your .env:");
        $this->line("HASHTAC_VERIFY_URL_SEALED={$sealed}");
        return self::SUCCESS;
    }
}
