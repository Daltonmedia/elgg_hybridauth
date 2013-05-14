<?php

/**
 * Elgg HybridAuth
 */
elgg_register_event_handler('init', 'system', 'elgg_hybridauth_init');

function elgg_hybridauth_init() {

	elgg_register_class('Hybrid_Auth', elgg_get_plugins_path() . 'elgg_hybridauth/classes/Hybrid/Auth.php');
	elgg_register_class('Hybrid_Endpoint', elgg_get_plugins_path() . 'elgg_hybridauth/classes/Hybrid/Endpoint.php');
	elgg_register_class('ElggHybridAuth', elgg_get_plugins_path() . 'elgg_hybridauth/classes/ElggHybridAuth.php');

	elgg_register_page_handler('hybridauth', 'elgg_hybridauth_page_handler');

	elgg_register_action('elgg_hybridauth/settings/save', elgg_get_plugins_path() . 'elgg_hybridauth/actions/settings/save.php', 'admin');
	elgg_register_action('hybridauth/register', elgg_get_plugins_path() . 'elgg_hybridauth/actions/register.php', 'public');

	elgg_extend_view('forms/login', 'hybridauth/login');
	elgg_extend_view('forms/hybridauth/login', 'hybridauth/aux_login');
	elgg_extend_view('forms/register', 'hybridauth/login');
	elgg_extend_view('core/settings/account', 'hybridauth/accounts');

	elgg_register_css('hybridauth.css', elgg_get_simplecache_url('css', 'hybridauth/core'));
	elgg_register_simplecache_view('css/hybridauth/core');

	elgg_register_js('hybridauth.js', elgg_get_simplecache_url('js', 'hybridauth/core'));
	elgg_register_simplecache_view('js/hybridauth/core');

	elgg_register_plugin_hook_handler('public_pages', 'walled_garden', 'elgg_hybridauth_public_pages');

	elgg_register_event_handler('login', 'user', 'elgg_hybridauth_aux_provider');
	//elgg_register_event_handler('login', 'user', 'elgg_hybridauth_authenticate_all_providers');
}

function elgg_hybridauth_page_handler($page) {

	$action = elgg_extract(0, $page);

	if (!isset($_SESSION['hybridauth'])) {
		$_SESSION['hybridauth'] = array(
			'friend_guid' => get_input('friend_guid'),
			'invitecode' => get_input('invitecode')
		);
	}

	switch ($action) {

		case 'authenticate' :
			$provider = get_input('provider');

			if (!$provider) {
				return false;
			}

			$ha = new ElggHybridAuth();

			try {
				$adapter = $ha->authenticate($provider);
				$profile = $adapter->getUserProfile();
			} catch (Exception $e) {
				$title = elgg_echo('error:default');
				$content = $e->getMessage();
				$layout = elgg_view_layout('error', array(
					'title' => $title,
					'content' => $content
						));
				echo elgg_view_page($title, $layout, 'error');
				return true;
			}

			if (elgg_is_logged_in()) {
				// User already has an account
				// Linking provider profile to an existing account
				elgg_set_plugin_user_setting("$provider:uid", $profile->identifier, elgg_get_logged_in_user_guid(), 'elgg_hybridauth');
				system_message(elgg_echo('hybridauth:link:provider', array($provider)));
				forward("settings/user/" . elgg_get_logged_in_user_entity()->username);
			}

			// Does this user exist?
			$options = array(
				'type' => 'user',
				'plugin_id' => 'elgg_hybridauth',
				'plugin_user_setting_name_value_pairs' => array(
					"$provider:uid" => $profile->identifier
				),
				'limit' => 0
			);

			$users = elgg_get_entities_from_plugin_user_settings($options);

			if ($users) {
				if (count($users) == 1) {
					// Profile for this provider exists
					if (!elgg_is_logged_in()) {
						login($users[0]);
						system_message(elgg_echo('hybridauth:login:provider', array($provider)));
						forward();
					}
				} else {
					// Do we have multiple accounts created for this profile???
					$title = elgg_echo('LoginException:Unknown');
					$content = $e->getMessage();
					$layout = elgg_view_layout('error', array(
						'title' => $title,
						'content' => $content
							));
					echo elgg_view_page($title, $layout, 'error');
					return true;
				}
			}

			// Let's see what data we have received from the provider and request the user to complete the registration process
			elgg_push_context('register');

			if ($profile->emailVerified) {
				$email = $profile->emailVerified;
			} else if ($profile->email) {
				$email = $profile->email;
			} else if (get_input('email')) {
				$email = urldecode(get_input('email'));
			}

			if ($email && $users = get_user_by_email($email)) {

				$title = elgg_echo('hybridauth:login');
				$content = elgg_view_form('hybridauth/login', array(
					'action' => 'action/login'
						), array(
					'username' => $email,
					'provider' => $provider,
					'provider_uid' => $profile->identifier
						));
			} else {

				$title = elgg_echo('hybridauth:register');
				$content = elgg_view_form('hybridauth/register', array(
						), array(
					'provider' => $provider,
					'profile' => $profile,
					'invitecode' => $_SESSION['hybridauth']['invitecode'],
					'friend_guid' => $_SESSION['hybridauth']['friend_guid']
						));
			}

			$layout = elgg_view_layout('one_column', array(
				'title' => $title,
				'content' => $content
					));

			echo elgg_view_page($title, $layout);

			return true;
			break;

		case 'endpoint' :
			try {
				Hybrid_Endpoint::process();
			} catch (Exception $e) {
				register_error($e->getMessage());
				forward();
			}
			break;
	}


	return false;
}

function elgg_hybridauth_public_pages($hook, $type, $return, $params) {

	$return[] = 'hybridauth/.*';
	return $return;
}

function elgg_hybridauth_aux_provider($event, $type, $user) {

	$aux_provider = get_input('aux_provider');
	$aux_provider_uid = get_input('aux_provider_uid');

	if ($aux_provider && $aux_provider_uid) {
		elgg_set_plugin_user_setting("$aux_provider:uid", $aux_provider_uid, $user->guid, 'elgg_hybridauth');
		system_message(elgg_echo('hybridauth:link:provider', array($aux_provider)));
	}

	return true;
}

function elgg_hybridauth_authenticate_all_providers($event, $type, $user) {

	$providers = unserialize(elgg_get_plugin_setting('providers', 'elgg_hybridauth'));

	foreach ($providers as $provider => $settings) {

		if ($settings['enabled']) {

			$adapter = false;

			$ha = new ElggHybridAuth();

			try {
				$adapter = $ha->getAdapter($provider);
			} catch (Exception $e) {
				// do nothing
			}

			if ($adapter) {
				if (elgg_get_plugin_user_setting("$provider:uid", $user->guid, 'elgg_hybridauth')) {
					try {
						$ha->authenticate($provider);
					} catch (Exception $e) {
						register_error($e->getMessage());
						register_error(elgg_echo('hybridauth:unlink:provider', array($provider)));
						elgg_unset_plugin_user_setting("$provider:uid", $user->guid, 'elgg_hybridauth');
					}
				}
			}
		}
	}

	return true;
}