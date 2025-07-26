<?php

namespace Anapars\HashtacCrypto\Facades;

use Illuminate\Support\Facades\Facade;

class HashtacCipher extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'hashtac.cipher';
    }
}
