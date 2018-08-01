<?php

namespace App\Security;

use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class UserVoter extends Voter
{

    const VIEW = 'view';
    const EDIT = 'edit';
    const DELETE = 'delete';


    protected function supports($attribute, $subject)
    {

        if (!in_array($attribute, array(self::VIEW, self::EDIT, self::DELETE))) {
            return false;
        }


        if (!$subject instanceof User) {
            return false;
        }

        return true;
    }


    private $decisionManager;

    public function __construct(AccessDecisionManagerInterface $decisionManager)
    {
        $this->decisionManager = $decisionManager;
    }

    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();

        if ($this->decisionManager->decide($token, array('ROLE_ADMIN'))) {
            return true;
        }


        if (!$user instanceof User) {
            return false;
        }


        /** @var User $profile */
        $profile = $subject;


        switch ($attribute) {
            case self::VIEW:
                return $this->canView($profile, $user);
            case self::EDIT:
                return $this->canEdit($profile, $user);
            case self::DELETE:
                return $this->canDelete($profile, $user);

        }

        throw new \LogicException('This code should not be reached!');
    }


    private function canView(User $profile, User $user)
    {

        if ($this->canEdit($profile, $user)) {
            return true;
        }
        return;
    }

    private function canEdit(User $profile, User $user)
    {
        return $user->getUsername() === $profile->getUsername();
    }

    private function canDelete(User $profile, User $user)
    {

        return $user->getUsername() === $profile->getUsername();
    }


}