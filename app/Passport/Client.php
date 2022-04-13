<?php

namespace App\Passport;

use Laravel\Passport\Client as BaseClient;

class Client extends BaseClient
{
    public function skipsAuthorization()
    {
        return true;
    }
}
