<?php

namespace App\Security;

use App\Entity\Post;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PostVoter extends Voter
{

    const VIEW = 'view';
    const EDIT = 'edit';
    const DELETE = 'delete';


    protected function supports($attribute, $subject)
    {

        if (!in_array($attribute, array(self::VIEW, self::EDIT, self::DELETE))) {
            return false;
        }


        if (!$subject instanceof Post) {
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


        if (!$user instanceof User){
            return false;
        }


        /** @var Post $post */
        $post = $subject;


        switch ($attribute) {
            case self::VIEW:
                return $this->canView($post, $user);
            case self::EDIT:
                return $this->canEdit($post, $user);
            case self::DELETE:
                return $this->canDelete($post, $user);

        }

        throw new \LogicException('This code should not be reached!');
    }


    private function canView(Post $post, User $user)
    {

        if ($this->canEdit($post, $user)) {
            return true;
        }
        return;
    }

    private function canEdit(Post $post, User $user)
    {
        return $user === $post->getAuthor();
    }

    private function canDelete(Post $post, User $user)
    {

        return $user === $post->getAuthor();
    }
}