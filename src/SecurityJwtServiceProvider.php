<?php

namespace Devim\Provider\SecurityJwtServiceProvider;

use Devim\Provider\SecurityJwtServiceProvider\Http\Authentication\Provider\JWTProvider;
use Devim\Provider\SecurityJwtServiceProvider\Http\EntryPoint\JWTAuthenticationEntryPoint;
use Devim\Provider\SecurityJwtServiceProvider\Http\Firewall\JWTListener;
use Devim\Provider\SecurityJwtServiceProvider\TokenEncoder\JWTTokenEncoder;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

class SecurityJwtServiceProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given container.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     *
     * @param Container $container A container instance
     *
     * @throws \InvalidArgumentException
     */
    public function register(Container $container)
    {
        $container['security.jwt.encoder'] = function () use ($container) {
            return new JWTTokenEncoder(
                $container['security.jwt.secret_key'],
                $container['security.jwt.algorithm'],
                $container['logger']
            );
        };

        /*
         * Class for usage custom listeners
         */
        $container['security.jwt.authentication_listener'] = function () use ($container) {
            return new JWTListener(
                $container['security.token_storage'],
                $container['security.authentication_manager'],
                $container['security.jwt.encoder'],
                $container['security.jwt.options']
            );
        };

        $container['security.entry_point.jwt'] = function () {
            return new JWTAuthenticationEntryPoint();
        };

        $container['security.authentication_listener.factory.jwt'] = $container->protect(function ($name) use (
            $container
        ) {
            $container['security.jwt.authentication_provider.' . $name] = function () use ($container, $name) {
                return new JWTProvider($container['security.user_provider.' . $name]);
            };

            $container['security.authentication_listener.' . $name . '.jwt'] = function () use ($container) {
                return $container['security.jwt.authentication_listener'];
            };
            $container['security.authentication_provider.' . $name . '.jwt'] = function () use ($container, $name) {
                return $container['security.jwt.authentication_provider.'. $name];
            };

            return [
                'security.authentication_provider.' . $name . '.jwt',
                'security.authentication_listener.' . $name . '.jwt',
                'security.entry_point.jwt',
                'pre_auth',
            ];
        });
    }
}
