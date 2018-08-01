<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\FormBuilderInterface;

class LoginType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('email', EmailType::class, [
                'label' => 'Email',
                'required' => 'required',
                'attr' => [
                    'class' => 'form-group'
                ]
            ])
            ->add('password', PasswordType::class, [
                'label' => 'Password',
                'required' => 'required',
                'attr' => [
                    'class' => 'form-group'
                ]
            ]);
    }
}