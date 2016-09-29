<?php

namespace Devimteam\Provider\SecurityJwtServiceProvider\TokenEncoder;

interface TokenEncoderInterface
{
    /**
     * @param $data
     * @param int $lifeTime
     *
     * @return mixed
     */
    public function encode($data, int $lifeTime);

    /**
     * @param string $token
     *
     * @return object
     */
    public function decode($token);
}
