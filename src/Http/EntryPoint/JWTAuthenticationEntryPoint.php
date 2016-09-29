<?php

namespace Devimteam\Provider\SecurityJwtServiceProvider\Http\EntryPoint;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Class JWTAuthenticationEntryPoint.
 */
class JWTAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * Starts the authentication scheme.
     *
     * @param Request $request The request that resulted in an AuthenticationException
     * @param AuthenticationException $authException The exception that started the authentication process
     *
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null) : JsonResponse
    {
        return new JsonResponse([
            'error' => $authException->getMessage(),
        ], Response::HTTP_UNAUTHORIZED);
    }
}
