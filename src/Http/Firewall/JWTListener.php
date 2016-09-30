<?php

namespace Devim\Provider\SecurityJwtServiceProvider\Http\Firewall;

use Devim\Provider\SecurityJwtServiceProvider\Http\Firewall\Exception\TokenException;
use Devim\Provider\SecurityJwtServiceProvider\Http\Token\JWTToken;
use Devim\Provider\SecurityJwtServiceProvider\TokenEncoder\TokenEncoderInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

/**
 * Class JWTListener.
 */
class JWTListener implements ListenerInterface
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var TokenEncoderInterface
     */
    private $encoder;

    /**
     * @var array
     */
    private $options;

    /**
     * JWTListener constructor.
     *
     * @param TokenStorageInterface $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param TokenEncoderInterface $encoder
     * @param array $options
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        TokenEncoderInterface $encoder,
        array $options
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->encoder = $encoder;
        $this->options = $options;
    }

    /**
     * @param GetResponseEvent $event
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \InvalidArgumentException
     * @throws \Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $dataToken = $this->getToken($request->headers->get($this->options['header_name'], null));

        if (null === $dataToken) {
            return;
        }

        try {
            $decodedToken = $this->encoder->decode($dataToken);

            $token = new JWTToken();
            $token->setTokenContext($decodedToken);

            $authToken = $this->authenticationManager->authenticate($token);

            $this->tokenStorage->setToken($authToken);
        } catch (TokenException $e) {
        }
    }

    /**
     * @param $token
     *
     * @return string | null
     */
    protected function getToken($token)
    {
        if (null === $token && null !== $this->options['token_prefix']) {
            return $token;
        }

        if (false !== strpos($token, $this->options['token_prefix'])) {
            $token = trim(str_replace($this->options['token_prefix'], '', $token));
        }

        return $token;
    }
}
