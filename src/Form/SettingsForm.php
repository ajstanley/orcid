<?php

namespace Drupal\orcid\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

class SettingsForm extends ConfigFormBase {
    public function getFormId() {
        return 'orcid_admin_settings';
    }

    protected function getEditableConfigNames() {
        return [
            'orcid.settings',
        ];
    }

    public function buildForm(array $form, FormStateInterface $form_state) {
        $config = $this->config('orcid.settings');
        $form['client_id'] = [
            '#type' => 'textfield',
            '#title' => $this->t('Client ID'),
            '#default_value' => $config->get('client_id'),
            '#description' => t('The client id value <client-id> from ORCID client application registration')
        ];
        $form['client_secret'] = [
            '#type' => 'textfield',
            '#title' => $this->t('Client secret'),
            '#default_value' => $config->get('client_secret'),
            '#description' => $this->t('The client secret value <client-secret> from ORCID client application registration'),
        ];
        $entityManager = \Drupal::service('entity_field.manager');
        $fields = $entityManager->getFieldDefinitions('user', 'user');
        $user_fields = array();
        foreach ($fields as $key => $field) {
            if (($field->getType() == 'string') && strpos($key, 'field_') === 0) {
                $user_fields[$key] = $this->t($field->getLabel());
            }
        }
        $form['name_field'] = [
            '#type' => 'select',
            '#options' => $user_fields,
            '#empty_option' => $this->t('- Select -'),
            '#title' => $this->t('User field for ORCID account name'),
            '#default_value' => $config->get('name_field'),
            '#description' => $this->t('This field will be used to store the ORCID author name.'),
        ];
        $form['allow_new'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Allow creation of new user?'),
            '#description' => $this->t('User will be created from ORCID Credentials.'),
            '#default_value' => $config->get('allow_new'),
        ];
        $form['activate'] = array(
            '#type' => 'checkbox',
            '#title' => t('Requires administrative approval?'),
            '#description' => t('Account will be created in inactive state.   Must be activated by site administrator'),
            '#default_value' => $config->get('activate'),
            '#states' => array(
                'invisible' => array(
                    ':input[name="allow_new"]' => array('checked' => FALSE),
                ),
            ),
        );
        $form['sandbox'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Sandbox'),
            '#default_value' => $config->get('sandbox'),
        ];
        return parent::buildForm($form, $form_state);
    }

    public function submitForm(array &$form, FormStateInterface $form_state) {
        $values = $form_state->getValues();
        $this->config('orcid.settings')
            ->set('client_id', $values['client_id'])
            ->set('client_secret', $values['client_secret'])
            ->set('name_field', $values['name_field'])
            ->set('sandbox', $values['sandbox'])
            ->set('allow_new', $values['allow_new'])
            ->set('activate', $values['activate'])
            ->save();
    }
}
