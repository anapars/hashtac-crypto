<?php

namespace Anapars\HashtacCrypto;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;
use Anapars\HashtacCrypto\Contracts\CipherContract;
use Anapars\HashtacCrypto\Services\Cipher;
use Illuminate\Support\Facades\File;

class HashtacCryptoServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/hashtac-crypto.php', 'hashtac-crypto');

        $this->app->singleton('hashtac.cipher', function ($app) {
            $config = $app['config']['hashtac-crypto'];

            return new Cipher(
                secret: $config['secret'],
                cipher: $config['cipher'],
                useHmac: $config['hmac'],
                hmacAlgo: $config['hmac_algo'],
            );
        });

        $this->app->alias('hashtac.cipher', CipherContract::class);
    }

    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                \Anapars\HashtacCrypto\Console\HashtacSealUrlCommand::class,
            ]);
        }

        $this->publishes([
            __DIR__ . '/../config/hashtac-crypto.php' => config_path('hashtac-crypto.php'),
        ], 'config');

        if (app()->environment('production')) {
            Guard::boot();
        }
    }
}
