<?php

namespace Devim\Provider\SecurityJwtServiceProvider\TokenEncoder;

use Devim\Provider\SecurityJwtServiceProvider\Http\Firewall\Exception\TokenException;
use Devim\Provider\SecurityJwtServiceProvider\Http\Firewall\Exception\TokenNotDecodedException;
use Devim\Provider\SecurityJwtServiceProvider\User\UserInterface;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 * Class JWTTokenEncoder.
 */
class JWTTokenEncoder implements TokenEncoderInterface
{
    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var array
     */
    private $allowedAlgorithm;

    /**
     * JWTTokenEncoder constructor.
     *
     * @param string $secretKey
     * @param array $allowedAlgorithm
     */
    public function __construct(string $secretKey, array $allowedAlgorithm)
    {
        $this->secretKey = $secretKey;
        $this->allowedAlgorithm = $allowedAlgorithm;
    }

    /**
     * @param mixed $data
     * @param int $lifeTime
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    public function encode($data, int $lifeTime) : string
    {
        $jwtData = [
            'id' => false,
            'username' => false,
            'exp' => time() + $lifeTime,
        ];

        if ($data instanceof UserInterface) {
            $jwtData['id'] = (int)$data->getId();
            $jwtData['username'] = (string)$data->getUsername();
        } elseif (is_array($data)) {
            if (!isset($data['id']) && !isset($data['username'])) {
                throw new \RuntimeException('Is not correct Array, keys should be id and username');
            }

            $jwtData['id'] = (int)$data['id'];
            $jwtData['username'] = (string)$data['username'];
        } else {
            throw new \RuntimeException('DatIs not correct format of the data to be UserInterface or Array');
        }

        return JWT::encode($jwtData, $this->secretKey);
    }

    /**
     * @param string $token
     *
     * @return object
     *
     * @throws \App\Provider\SecurityJwtServiceProvider\Http\Firewall\Exception\TokenException
     */
    public function decode($token)
    {
        try {
            return JWT::decode($token, $this->secretKey, $this->allowedAlgorithm);
        } catch (\DomainException $e) {
            throw new TokenException('Algorithm was not provided');
        } catch (SignatureInvalidException $e) {
            throw new TokenException('Provided JWT was invalid because the signature verification failed');
        } catch (BeforeValidException $e) {
            throw new TokenException('Signature invalid');
        } catch (ExpiredException $e) {
            throw new TokenException('Provided JWT has since expired, as defined by the \'exp\' claim');
        } catch (\UnexpectedValueException $e) {
            throw new TokenException('Provided JWT was invalid');
        }
    }
}
