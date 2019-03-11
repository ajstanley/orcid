<?php

namespace Drupal\orcid\Controller;

use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\Core\Controller\ControllerBase;
use Drupal\user\Entity\User;
use League\OAuth2\Client\Provider\GenericProvider;

class OauthController extends ControllerBase {
    public function finish($text = '') {
        $destination = $_SESSION['orcid']['destination'];
        if (isset($destination)) {
            $response = new TrustedRedirectResponse($destination);
            $this->messenger->addMessage($text);
            unset($_SESSION['orcid']['destination']);
            return $response;
        }
        $element = [
            '#markup' => $this->t($text),
        ];
        return $element;
    }

    public function redirectPage() {
        if (isset($_GET['destination'])) {
            $_SESSION['orcid']['destination'] = $_GET['destination'];
        }

        $config = \Drupal::config('orcid.settings');
        //http://members.orcid.org/api/tokens-through-3-legged-oauth-authorization
        //Public API only at this moment
        $provider = new GenericProvider([
            'clientId' => $config->get('client_id'),
            // The client ID assigned to you by the provider
            'clientSecret' => $config->get('client_secret'),
            // The client password assigned to you by the provider
            'redirectUri' => Url::fromUri('base:/orcid/oauth', ['absolute' => TRUE])
                ->toString(),
            'urlAuthorize' => !$config->get('sandbox') ? 'https://orcid.org/oauth/authorize' : 'https://sandbox.orcid.org/oauth/authorize',
            'urlAccessToken' => !$config->get('sandbox') ? 'https://pub.orcid.org/oauth/token' : 'https://sandbox.orcid.org/oauth/token',
            'urlResourceOwnerDetails' => !$config->get('sandbox') ? 'http://pub.orcid.org/v1.2' : 'https://pub.sandbox.orcid.org/v1.2',
        ]);

        if (!isset($_GET['code'])) {
            $options = [
                'scope' => ['/authenticate']
            ];
            $authorizationUrl = $provider->getAuthorizationUrl($options);
            $response = new TrustedRedirectResponse($authorizationUrl);
            return $response;
        }

        try {
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);

            $token = $accessToken->getToken();
            $_SESSION['orcid']['token'] = $token;
            $values = $accessToken->getValues();
            $account = \Drupal::currentUser()->getAccount();


            $query = \Drupal::entityQuery('user');
            $query->condition('field_orcid_id', $values['orcid']);
            $result = $query->execute();

            foreach ($result as $item => $uid) {
                //ORCID in record
                //anonymous user
                if ($account->id() == 0) {
                    if ($user = User::load($uid)) {
                        user_login_finalize($user);
                        $message = $this->t('You have Logged in with ORCID!')->render();
                        if (!$user->isActive()) {
                            $message = $this->t("Your account has been created from your ORCID credentials and is awaiting administrative approval")->render();
                        }
                        return $this->finish($message);
                    }
                }

                if ($account->id() == $uid) {//ORCID match UID
                    return $this->finish('Your ORCID has been connected!');
                } else {
                    //TODO: What if user account can't match ORCID record
                }
            }
            //Existing User
            if ($account->id()) {
                $user = \Drupal\user\Entity\User::load($account->id());
                $user->set('field_orcid_id', $values['orcid']);

                return $this->finish('Your ORCID has been connected!');
            }
            //New user with New ORCID
            if ($account->id() == 0) {
                if (!$config->get('allow_new')) {
                    $message = t("No user has this ORCID ID.  Please create account.")->render();
                    return $this->finish($message);
                }
                $new_user = [
                    'name' => $values['name'],
                    'mail' => '',
                    'pass' => $token,
                    'status' => $config->get('activate'),
                    $config->get('name_field') => $values['orcid'],
                ];

                $user = User::create($new_user);
                $user->save();

                user_login_finalize($user);
                $message = t('Your account has been created with your ORCID credentials!')->render();
                if (!$config->get('activate')) {
                    $message = t("Your account has been created from your ORCID credentials and is awaiting administrative approval")->render();
                }
                return $this->finish($message);
            }
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            \Drupal::logger('orcid')->error($e->getMessage());
        }

        return $this->finish('Failed!');
    }
}
