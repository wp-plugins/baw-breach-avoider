<?php
/*
Plugin Name: BAW BREACH Avoider
Description: Avoid to be easily the target of the new HTTPS BREACH vulnerability <em>(see <a target="_blank"href="http://www.kb.cert.org/vuls/id/987798">http://www.kb.cert.org/vuls/id/987798</a> - Aug. 2013)</em>.
Author: juliobox
Author URI: http://www.boiteaweb.fr
Plugin URI: http://www.boiteaweb.fr
Version: 1.0
*/

defined( 'ABSPATH' ) or	die( 'Cheatin\' uh?' );

defined( 'BBA_REPEATER' ) or define( 'BBA_REPEATER', 2 );
defined( 'BBA_NONCE_LENGTH' ) or define( 'BBA_NONCE_LENGTH', 10 ); // Min 4, Max 32, Default 10

if( !function_exists( 'wp_verify_nonce' ) ) :
	function wp_verify_nonce( $nonce, $action = -1 )
	{
		/* Redo the new nonce */
		// Set a correct length
		$BBA_NONCE_LENGTH = min( 32, max( 4, BBA_NONCE_LENGTH ) );
		// Get a salt
		$NONCE_SALT = wp_salt( 'nonce' );
		// Get the correct nonce from the friendly format
		if( !( strlen( $none ) & 1 ) )
			$nonce .= '0'; // Avoid a PHP Warning in PHP 5.4.1+
		$nonce = hex2bin( $nonce );
		// Reverse the XORed nonce
		for( $i=0; $i<strlen($nonce); $i++ )
            $nonce{$i} = $nonce{$i} ^ $NONCE_SALT{$i%BBA_NONCE_LENGTH};
        // Retreive the random key
		$_rand = substr( $nonce, $BBA_NONCE_LENGTH );
		// Get the real new nonce
		$nonce = substr( $nonce, 0, $BBA_NONCE_LENGTH );

	    /* From core + mods */
		$user = wp_get_current_user();
		$uid = (int)$user->ID;
		if( !$uid )
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );

		$wp_nonce_tick = wp_nonce_tick();

		// Nonce generated 0-12 hours ago
		// 0 instead of -12 for the 2nd param of substr()
		// + $_rand in wp_hash(), this is the trick
		if( substr( wp_hash( $wp_nonce_tick . $action . $uid . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH ) === $nonce )
			return 1;

		// Nonce generated 12-24 hours ago
		// 0 instead of -12 for the 2nd param of substr()
		// + $_rand in wp_hash(), this is the trick
		if( substr( wp_hash( ( $wp_nonce_tick - 1 ) . $action . $uid . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH ) === $nonce )
			return 2;

		// Invalid nonce
		return false;
	}
endif;

if( !function_exists( 'wp_create_nonce' ) ) :
	function wp_create_nonce( $action = -1 )
	{
		/* From core */
		$user = wp_get_current_user();
		$uid = (int) $user->ID;
		if( !$uid )
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );

		$wp_nonce_tick = wp_nonce_tick();

		/* Do the new nonce */
		$_rand = '';
		// Set a correct repeater, 1 min
		$BBA_REPEATER = max( 1, BBA_REPEATER );
		// Set a correct length
		$BBA_NONCE_LENGTH = min( 32, max( 4, BBA_NONCE_LENGTH ) );
		// Get a salt
		$NONCE_SALT = wp_salt( 'nonce' );
		// Create the random string
		for( $i=0; $i < $BBA_REPEATER; $i++)
			$_rand .= dechex( rand( 16, 255 ) );
		// Create the nonce with $_rand, this is the trick
		$nonce = substr( wp_hash( $wp_nonce_tick . $action . $uid . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH );
		// We had the rand into the string
		$nonce .= $_rand;
		// Obfuscate with XOR
		for( $i=0; $i<strlen($nonce); $i++ )
            $nonce{$i} = $nonce{$i} ^ $NONCE_SALT{$i%BBA_NONCE_LENGTH};
        // Get a friendly nonce
        $nonce = bin2hex( $nonce );
        
		return $nonce;
	}
endif;

add_action( 'admin_footer', 'bba_add_dynamic_content' );
add_action( 'wp_footer', 'bba_add_dynamic_content' );
function bba_add_dynamic_content()
{
	$md5 = md5( microtime( true ) );
	$repeat = str_repeat( chr( rand( 33, 126 ) ), (int)rand( 1, 32 ) );
	echo '<span style="display:none">'.$md5.$repeat.'</span>';
}

if( !function_exists( 'baw_nonce_user_logged_out' ) ):
	add_filter( 'nonce_user_logged_out', 'baw_nonce_user_logged_out' );
	function baw_nonce_user_logged_out()
	{
		return md5( baw_get_IP() );
	}
endif;

if( !function_exists( 'baw_get_IP' ) ):
	function baw_get_IP()
	{
		if( getenv( 'HTTP_CLIENT_IP' ) )
			$IP = getenv( 'HTTP_CLIENT_IP' );
		elseif( getenv( 'HTTP_X_FORWARDED_FOR' ) )
			$IP = getenv( 'HTTP_X_FORWARDED_FOR' );
		elseif( getenv( 'HTTP_X_FORWARDED' ) )
			$IP = getenv( 'HTTP_X_FORWARDED' );
		elseif( getenv( 'HTTP_FORWARDED_FOR' ) )
			$IP = getenv( 'HTTP_FORWARDED_FOR' );
		elseif( getenv( 'HTTP_FORWARDED' ) )
			$IP = getenv( 'HTTP_FORWARDED' );
		else
			$IP = $_SERVER['REMOTE_ADDR'];
		return $IP;
	}
endif;