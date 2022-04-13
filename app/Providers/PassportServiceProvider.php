<?php

namespace App\Providers;

use App\Passport\Client;
use App\Passport\IdTokenResponse;
use Laravel\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Server\AuthorizationServer;

class PassportServiceProvider extends Passport\PassportServiceProvider
{
    public function boot()
    {
        parent::boot();

        Passport\Passport::routes();

        Passport\Passport::useClientModel(Client::class);

        Passport\Passport::tokensCan(['openid'  => 'Enable OpenID Connect']);
    }

    public function makeAuthorizationServer(): AuthorizationServer
    {
        $cryptKey = $this->makeCryptKey('private');

        $signingKey = $cryptKey->getKeyPath()
            ? InMemory::file($cryptKey->getKeyPath())
            : InMemory::plainText($cryptKey->getKeyContents());

        $responseType = new IdTokenResponse(
            Configuration::forSymmetricSigner(
                app(Sha256::class),
                $signingKey,
            ),
        );

        return new AuthorizationServer(
            app(Passport\Bridge\ClientRepository::class),
            app(Passport\Bridge\AccessTokenRepository::class),
            app(Passport\Bridge\ScopeRepository::class),
            $cryptKey,
            app('encrypter')->getKey(),
            $responseType,
        );
    }
}
