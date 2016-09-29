<?php

use Silex\Application;
use Devimteam\Provider\SecurityJwtServiceProvider\SecurityJwtServiceProvider;
use Devimteam\Provider\SecurityJwtServiceProvider\TokenEncoder\JWTTokenEncoder;
use Devimteam\Provider\SecurityJwtServiceProvider\Http\Firewall\JWTListener;
use Devimteam\Provider\SecurityJwtServiceProvider\Http\EntryPoint\JWTAuthenticationEntryPoint;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\AnonymousAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

class SecurityJwtServiceProviderTest extends PHPUnit_Framework_TestCase
{
    protected $app;
    protected $securityJwtService;

    public function setUp()
    {
        $this->app = new Application();
        $this->app->register(new SecurityJwtServiceProvider());

        $this->app['logger'] = 'logger';
        $this->app['security.token_storage'] = new TokenStorage();
        $this->app['security.jwt.secret_key'] = 'foobarino';
        $this->app['security.authentication_providers'] = [new AnonymousAuthenticationProvider('secret')];
        $this->app['security.authentication_manager'] = function ($app) {
            $manager = new AuthenticationProviderManager($app['security.authentication_providers']);
            $manager->setEventDispatcher($app['dispatcher']);

            return $manager;
        };
        $this->app['security.jwt.algorithm'] = ['HS256'];
        $this->app['security.jwt.options'] = [
            'header_name' => 'foo',
            'token_prefix' => 'barr',
        ];
    }

    public function testSecurityJwtServiceProvider()
    {
        self::assertArrayHasKey('security.jwt.encoder', $this->app);
        self::assertInstanceOf(JWTTokenEncoder::class, $this->app['security.jwt.encoder']);

        self::assertArrayHasKey('security.jwt.authentication_listener', $this->app);
        self::assertInstanceOf(JWTListener::class, $this->app['security.jwt.authentication_listener']);

        self::assertArrayHasKey('security.entry_point.jwt', $this->app);
        self::assertInstanceOf(JWTAuthenticationEntryPoint::class, $this->app['security.entry_point.jwt']);
    }
}
