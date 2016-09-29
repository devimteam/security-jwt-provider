<?php

namespace Devimteam\Provider\SecurityJwtServiceProvider\Http\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Class JWTToken.
 */
class JWTToken extends AbstractToken
{
    /**
     * @var mixed
     */
    protected $tokenContext;

    /**
     * @return mixed
     */
    public function getTokenContext()
    {
        return $this->tokenContext;
    }

    /**
     * @param mixed $tokenContext
     */
    public function setTokenContext($tokenContext)
    {
        $this->tokenContext = $tokenContext;
    }

    /**
     * Returns the user credentials.
     *
     * @return mixed The user credentials
     */
    public function getCredentials()
    {
        return '';
    }
}
