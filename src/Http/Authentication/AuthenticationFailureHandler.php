<?php

namespace Devim\Provider\SecurityJwtServiceProvider\Http\Authentication;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;

/**
 * Class AuthenticationFailureHandler.
 */
class AuthenticationFailureHandler extends DefaultAuthenticationFailureHandler
{
    /**
     * @param Request $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception) : JsonResponse
    {
        $response = [
            'error' => 'Invalid credentials',
            'message' => $exception->getMessage(),
        ];

        return new JsonResponse($response, 403);
    }
}