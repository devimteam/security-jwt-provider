<?php

namespace Devim\Provider\SecurityJwtServiceProvider\Http\Authentication;

use Devim\Provider\SecurityJwtServiceProvider\User\UserInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;

/**
 * Class AuthenticationSuccessHandler.
 */
class AuthenticationSuccessHandler extends DefaultAuthenticationSuccessHandler
{
    /**
     * @param Request $request
     * @param TokenInterface $token
     *
     * @return JsonResponse
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token) : JsonResponse
    {
        /** @var UserInterface $user */
        $user = $token->getUser();
        $response = [
            'id' => $user->getId(),
            'username' => $user->getUsername(),
            'token' => $token->serialize(),
        ];

        return new JsonResponse($response);
    }
}
