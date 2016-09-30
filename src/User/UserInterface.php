<?php

namespace Devim\Provider\SecurityJwtServiceProvider\User;

use Symfony\Component\Security\Core\User\UserInterface as BaseUserInterface;

/**
 * Interface UserInterface.
 */
interface UserInterface extends BaseUserInterface
{
    /**
     * @return int|null
     */
    public function getId();
}
