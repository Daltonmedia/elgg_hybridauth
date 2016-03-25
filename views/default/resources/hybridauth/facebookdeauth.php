<?php
$signed_request = get_input('signed_request');
$output = parse_signed_request($signed_request);
function parse_signed_request($signed_request) {
  list($encoded_sig, $payload) = explode('.', $signed_request, 2); 

  $secret = elgg_get_plugin_setting('providers', $plugin_name = "elgg_hybridauth"); 
  $secret = unserialize($secret)['Facebook']['keys']['secret'];

  // decode the data
  $sig = base64_url_decode($encoded_sig);
  $data = json_decode(base64_url_decode($payload), true);

  // confirm the signature
  $expected_sig = hash_hmac('sha256', $payload, $secret, $raw = true);
  if ($sig !== $expected_sig) {
    error_log('Bad Signed JSON signature!');
    return null;
  }

  return $data;
}

function base64_url_decode($input) {
  return base64_decode(strtr($input, '-_', '+/'));
}
$options = array(
			'private_setting_name' => 'plugin:user_setting:elgg_hybridauth:Facebook:uid',
			'private_setting_value' => $output['user_id'],
			'limit' => 1,
		);
$user = elgg_get_entities_from_private_settings($options)[0]; 
$session_name = get_input('session_name');
$session_handle = get_input('session_handle');
$ha_session = new Elgg\HybridAuth\Session($user, $session_name, $session_handle);
$ha_provider = $ha_session->getProvider('Facebook');
if ($ha_session->deauthenticate($ha_provider)) {
	notify_user($user->guid,
	   elgg_get_site_entity()->guid,
	   elgg_echo('hybridauth:facebook:user:remote_deauthorized:mail:subject', array(), $user->language),
	   elgg_echo('hybridauth:facebook:user:remote_deauthorized:mail:body', array($user->username, $password), $user->language),
	   array(),
	   'email');
} else {
	error_log('Something went wrong');
}


