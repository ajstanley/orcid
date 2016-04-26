<?php
namespace Drupal\orcid\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

class SettingsForm extends ConfigFormBase {
    public function getFormId() {
        return 'orcid_admin_settings';
    }
    protected function getEditableConfigNames()
    {
        return [
            'orcid.settings',
        ];
    }
    public function buildForm(array $form, FormStateInterface $form_state) {
        $config = $this->config('orcid.settings');
        $form['client_id'] = array('#type' => 'textfield',
            '#title' => t('Client ID'),
            '#default_value' => $config->get('client_id'),
            '#description' => t('The client id value <client-id> from ORCID client application registration')
        );
        $form['client_secret'] = array('#type' => 'textfield',
            '#title' => t('Client secret'),
            '#default_value' => $config->get('client_secret'),
            '#description' => t('The client secret value <client-secret> from ORCID client application registration'),
        );
        return parent::buildForm($form, $form_state);
    }
    public function submitForm(array &$form, FormStateInterface $form_state) {
        $values = $form_state->getValues();
        $this->config('orcid.settings')
            ->set('client_id', $values['client_id'])
            ->set('client_secret', $values['client_secret'])
            ->save();
    }
}