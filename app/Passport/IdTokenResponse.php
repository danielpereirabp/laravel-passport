<?php

namespace App\Passport;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

class IdTokenResponse extends BearerTokenResponse
{
    private Configuration $config;

    public function __construct(Configuration $config)
    {
        $this->config = $config;
    }

    protected function getBuilder(AccessTokenEntityInterface $accessToken): Builder
    {
        $dateTimeImmutableObject = new DateTimeImmutable();

        return $this->config
            ->builder()
            ->withHeader('kid', 'kid_value')
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy('https://' . $_SERVER['HTTP_HOST'])
            ->issuedAt($dateTimeImmutableObject)
            ->expiresAt($dateTimeImmutableObject->add(new DateInterval('PT1H')))
            ->relatedTo($accessToken->getUserIdentifier());
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (!$this->hasOpenIDScope(...$accessToken->getScopes())) {
            return [];
        }

        $builder = $this->getBuilder($accessToken);

        $token = $builder->getToken(
            $this->config->signer(),
            $this->config->signingKey(),
        );

        return ['id_token' => $token->toString()];
    }

    private function hasOpenIDScope(ScopeEntityInterface ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }

        return false;
    }
}
