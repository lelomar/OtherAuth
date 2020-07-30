<?php

/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.joomla
 *
 * @copyright   Copyright (C) 2005 - 2020 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Joomla Authentication plugin
 *
 * @since  1.5
 */
class PlgAuthenticationLaravelApi extends JPlugin{
    
    private $Driver;
    private $Host;
    private $UserName;
    private $Password;
    private $DataBase;


    public function __construct(&$subject, $config = array()){
		// Get the parameters.
        $params = json_decode($config["params"], true);
        // DEFAULT
        $this->Driver   = $params["driver"];
        $this->Host     = $params["host"];
        $this->UserName = $params["username"];
        $this->Password = $params["password"];
        $this->DataBase = $params["database"];
        // BASE
        $this->UserTable = $params["user_table"];
        $this->UserNameField = $params["username_field"];
        $this->PasswordField = $params["password_field"];
        $this->HashingAlgo = $params["hashing"];

        $this->AuthMethod = $params["auth_method"];

        // OPTIONAL
        $this->AuthorizedRole = $params["authorized_role"];

        $this->UserFieldFKR = $params["FKR_RolePKR"];           // Foreign Key Role (Primary Key Role)
        $this->RolesNameTable = $params["roles_table_name"];    // Table Name of Roles
        $this->RolesNameField = $params["roles_table_field"];   // Name Field of Roles Table
        $this->RolesFieldPKR = $params["roles_id"];             // Primary Key of Role Table


        $this->RolesUsersNameTable = $params["roles_users"];
        $this->UserFieldPKU = $params["user_fieldPKU"];
        $this->FKRolesPKU = $params["roles_users_role_id"];
        $this->FKUsersPKU = $params["user_id"];



    }


    /**
     * This method should handle any authentication and report back to the subject
     *
     * @param   array   $credentials  Array holding the user credentials
     * @param   array   $options      Array of extra options
     * @param   object  &$response    Authentication response object
     *
     * @return  void
     *
     * @since   1.5
     */

    public function onUserAuthenticate($credentials, $options, &$response)
    {

        $option['driver']   = $this->Driver;        //'mysql';
        $option['host']     = $this->Host;          //'localhost';
        $option['user']     = $this->UserName;      // 'oravta_servizi';
        $option['password'] = $this->Password;      // 'EpuggA2020';
        $option['database'] = $this->DataBase;      // 'oravta_servizi';
        $option['prefix']   = '';

        $response->type = 'Joomla';

        $db = JDatabaseDriver::getInstance($option);

		// Check if Usertable is provided, if not you cannot go throught
        if($this->UserTable == ""){
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('Accesso Fallito: Nessuna tabella indicata');
            return;
        }
        // Joomla does not like blank passwords
        if (empty($credentials['password']))
        {
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

            return;
        }


        $exists = false;
        switch ($this->AuthMethod){
            case "Basic":
                $query = $db->getQuery(true)
                    ->select('*')
                    ->from($this->UserTable)
                    ->where($this->UserNameField . '=' . $db->quote($credentials['username']))
                ;

                $db->setQuery($query);
                $result= $db->loadAssocList();
                $i=0;
                $result[$i] = $result[0];
                $exists = true;
                break;
            case "M1":
                $query = $db->getQuery(true)
                    ->select('*')
                    ->from($this->UserTable)
                    ->join('INNER', $db->quoteName($this->RolesNameTable, 'r') . 'ON r.' . $this->RolesFieldPKR . ' = ' . $this->UserTable . '.' . $this->UserFieldFKR)
                    ->where($this->UserNameField . '=' . $db->quote($credentials['username']))
                ;

                // Add control about role == authorizedrole
                $db->setQuery($query);
                $result= $db->loadAssocList();
                $i=0;
                $result[$i] = $result[0];
                if($result[$i]["role"] == $this->AuthorizedRole){
                    $exists = true;
                }
                break;
            case "MM":
                //die(var_dump($db->quoteName($this->RolesUsersNameTable, 'r') . 'ON r.' . $this->FKUsersPKU . ' = ' . $this->UserTable . '.' . $this->UserFieldPKU . "\n" .$db->quoteName($this->RolesNameTable, 'q') . 'ON r.' . $this->FKRolesPKU . ' = ' . 'q.' . $this->RolesFieldPKR));
                $query = $db->getQuery(true)
                    ->select('*')
                    ->from($this->UserTable)
                    ->join('INNER', $db->quoteName($this->RolesUsersNameTable, 'r') . 'ON r.' . $this->FKUsersPKU . ' = ' . $this->UserTable . '.' . $this->UserFieldPKU)
                    ->join('INNER', $db->quoteName($this->RolesNameTable, 'q') . 'ON r.' . $this->FKRolesPKU . ' = ' . 'q.' . $this->RolesFieldPKR)
                    ->where($this->UserNameField . '=' . $db->quote($credentials['username']))
                ;

                $db->setQuery($query);
                $result= $db->loadAssocList();
                $i=0;
                $result[$i] = $result[0];
                if($result[$i]["role"] == $this->AuthorizedRole){
                    $exists = true;
                }
                break;
        }

        if ($exists) {


            if($this->HashingAlgo == "md5"){
                // I strongly recommend you not to use md5 as hashing algorithm
                // but to make it easier for the plugin user to test it I implemented this control
                $match = md5($credentials['password']) == $result[$i]['password'];
            }
            /* Resolve mcrypt problem
            if($this->HashingAlgo == "blowfish"){
                $match = $this->encrypt_blowfish($credentials['password'], $this->HashingKey) == $result[$i]['password'];
                var_dump($match);
                var_dump($result[$i]['password']);
                var_dump($this->encrypt_blowfish($credentials['password'], $this->HashingKey));
                die();
            } */
            else {
                // password_verify — Verifies that a password matches a hash
                // The hash can be created by the usage of password_hash() that creates a new password hash using a strong one-way hashing algorithm.

                $match = password_verify($credentials['password'], $result[$i]['password']);
            }

            if ($match === true) {
                // Bring this in line with the rest of the system
                //die(var_dump($result[$i]));
                //$user = JUser::getInstance(10);
                $user = new stdClass();
                $lang = JFactory::getLanguage();

                $user->email = $result[$i]['email'];
                unset($user->groups);
                $user->name = $result[$i]['name'];
                $user->params["language"]= $lang->getName();
                $user->params["admin_language"]= $lang->getName();


                $response->email    = $user->email;
                $response->fullname = $user->name;

                $response->language = $user->params['language'];
                $response->status        = JAuthentication::STATUS_SUCCESS;
                $response->error_message = '';
            } else {
                // Invalid password
                $response->status        = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
            }
        } else {
            // Let's hash the entered password even if we don't have a matching user for some extra response time
            // By doing so, we mitigate side channel user enumeration attacks
            JUserHelper::hashPassword($credentials['password']);

            if(!$result){
                // Invalid User
                $response->status        = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
            } else {

                $response->status        = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('Accesso Negato: Nessun ruolo associato');
            }
        }

        // Check the two factor authentication

        if ($response->status === JAuthentication::STATUS_SUCCESS) {
            $methods = JAuthenticationHelper::getTwoFactorMethods();

            if (count($methods) <= 1) {
                // No two factor authentication method is enabled
                return;
            }

            JModelLegacy::addIncludePath(JPATH_ADMINISTRATOR . '/components/com_users/models', 'UsersModel');

            /** @var UsersModelUser $model */
            $model = JModelLegacy::getInstance('User', 'UsersModel', array('ignore_request' => true));

            // Load the user's OTP (one time password, a.k.a. two factor auth) configuration
            if (!array_key_exists('otp_config', $options)) {
                $otpConfig             = $model->getOtpConfig($result[$i]['id']);
                $options['otp_config'] = $otpConfig;
            } else {
                $otpConfig = $options['otp_config'];
            }

            // Check if the user has enabled two factor authentication
            if (empty($otpConfig->method) || ($otpConfig->method === 'none')) {
                // Warn the user if they are using a secret code but they have not
                // enabled two factor auth in their account.
                if (!empty($credentials['secretkey'])) {
                    try {
                        $app = JFactory::getApplication();

                        $this->loadLanguage();

                        $app->enqueueMessage(JText::_('PLG_AUTH_JOOMLA_ERR_SECRET_CODE_WITHOUT_TFA'), 'warning');
                    } catch (Exception $exc) {
                        // This happens when we are in CLI mode. In this case
                        // no warning is issued
                        return;
                    }
                }

                return;
            }

            // Try to validate the OTP
            FOFPlatform::getInstance()->importPlugin('twofactorauth');

            $otpAuthReplies = FOFPlatform::getInstance()->runPlugins('onUserTwofactorAuthenticate', array($credentials, $options));

            $check = false;

            /*
             * This looks like noob code but DO NOT TOUCH IT and do not convert
             * to in_array(). During testing in_array() inexplicably returned
             * null when the OTEP begins with a zero! o_O
             */
            if (!empty($otpAuthReplies))
            {
                foreach ($otpAuthReplies as $authReply)
                {
                    $check = $check || $authReply;
                }
            }

            // Fall back to one time emergency passwords
            if (!$check)
            {
                // Did the user use an OTEP instead?
                if (empty($otpConfig->otep))
                {
                    if (empty($otpConfig->method) || ($otpConfig->method === 'none'))
                    {
                        // Two factor authentication is not enabled on this account.
                        // Any string is assumed to be a valid OTEP.

                        return;
                    }
                    else
                    {
                        /*
                         * Two factor authentication enabled and no OTEPs defined. The
                         * user has used them all up. Therefore anything they enter is
                         * an invalid OTEP.
                         */
                        $response->status        = JAuthentication::STATUS_FAILURE;
                        $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');

                        return;
                    }
                }

                // Clean up the OTEP (remove dashes, spaces and other funny stuff
                // our beloved users may have unwittingly stuffed in it)
                $otep  = $credentials['secretkey'];
                $otep  = filter_var($otep, FILTER_SANITIZE_NUMBER_INT);
                $otep  = str_replace('-', '', $otep);
                $check = false;

                // Did we find a valid OTEP?
                if (in_array($otep, $otpConfig->otep))
                {
                    // Remove the OTEP from the array
                    $otpConfig->otep = array_diff($otpConfig->otep, array($otep));

                    $model->setOtpConfig($result->id, $otpConfig);

                    // Return true; the OTEP was a valid one
                    $check = true;
                }
            }

            if (!$check)
            {
                $response->status        = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');
            }
        }
    }
}
