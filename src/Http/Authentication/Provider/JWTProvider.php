<?php

namespace Devim\Provider\SecurityJwtServiceProvider\Http\Authentication\Provider;

use Devim\Provider\SecurityJwtServiceProvider\Http\Token\JWTToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class JWTProvider.
 */
class JWTProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * JWTProvider constructor.
     *
     * @param UserProviderInterface $userProvider
     */
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * @param TokenInterface $token
     *
     * @return TokenInterface
     *
     * @throws \InvalidArgumentException
     * @throws BadCredentialsException
     */
    public function authenticate(TokenInterface $token) : TokenInterface
    {
        $username = $token instanceof JWTToken ? $token->getTokenContext()->username : $token->getUsername();

        try {
            $user = $this->userProvider->loadUserByUsername($username);

            $lastContext = $token->getTokenContext();

            $token = new JWTToken($user->getRoles());
            $token->setTokenContext($lastContext);
            $token->setAuthenticated(true);
            $token->setUser($user);

            return $token;
        } catch (UsernameNotFoundException $e) {
            throw new BadCredentialsException('Bad credentials.', 0, $e);
        }
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function supports(TokenInterface $token) : bool
    {
        return $token instanceof JWTToken;
    }
}
