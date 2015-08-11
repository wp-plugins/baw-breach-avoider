<?php
/*
Plugin Name: BAW BREACH Avoider
Description: Avoid to be easily the target of the new HTTPS BREACH vulnerability <em>(see <a target="_blank"href="http://www.kb.cert.org/vuls/id/987798">http://www.kb.cert.org/vuls/id/987798</a> - Aug. 2013)</em>.
Plugin URI: http://blog.secupress.fr/breach-avoider-comment-eviter-hack-https-48.html
Version: 1.3
Author: Julio Potier
Author URI: http://wp-rocket.me
*/

defined( 'ABSPATH' ) or	die( 'Cheatin\' uh?' );

defined( 'BBA_REPEATER' ) or define( 'BBA_REPEATER', 2 );
defined( 'BBA_NONCE_LENGTH' ) or define( 'BBA_NONCE_LENGTH', 10 ); // Min 4, Max 32

function bba_hex2bin( $hexstr ) {
    $n = strlen( $hexstr ); 
    $sbin = '';   
    $i = 0; 
    while( $i < $n ) {       
        $a = substr( $hexstr, $i, 2 );
        $c = pack( "H*", $a );
        if ( 0 === $i ) {
        	$sbin = $c;
        } else {
        	$sbin .= $c;
        }
        $i += 2;
    }
    return $sbin;
} 

if ( ! function_exists( 'wp_verify_nonce' ) ) :
	function wp_verify_nonce( $nonce, $action = -1 ) {
		/* Redo the new nonce */
		// Set a correct length
		$BBA_NONCE_LENGTH = min( 32, max( 4, BBA_NONCE_LENGTH ) );
		// Get a salt
		$NONCE_SALT = wp_salt( 'nonce' );
		// Get the correct nonce from the friendly format
		$nonce = bba_hex2bin( $nonce );
		// Reverse the XORed nonce
		for( $i = 0; $i < strlen( $nonce ); $i++ )
            $nonce{ $i } = $nonce{ $i } ^ $NONCE_SALT{ $i % BBA_NONCE_LENGTH };
        // Retreive the random key
		$_rand = substr( $nonce, $BBA_NONCE_LENGTH );
		// Get the real new nonce
		$nonce = substr( $nonce, 0, $BBA_NONCE_LENGTH );

	    /* From core + mods */
		$user = wp_get_current_user();
		$uid = (int) $user->ID;
		if ( ! $uid ) {
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}
		$token = wp_get_session_token();
		$wp_nonce_tick = wp_nonce_tick();

		// Nonce generated 0-12 hours ago
		// 0 instead of -12 for the 2nd param of substr()
		// + $_rand in wp_hash(), this is the trick
		$expected = substr( wp_hash( $wp_nonce_tick . '|' . $action . '|' . $uid . '|' . $token . '|' . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH );
		if ( hash_equals( $expected, $nonce ) ) {
			return 1;
		}

		// Nonce generated 12-24 hours ago
		// 0 instead of -12 for the 2nd param of substr()
		// + $_rand in wp_hash(), this is the trick
		$expected = substr( wp_hash( $wp_nonce_tick - 1 . '|' . $action . '|' . $uid . '|' . $token . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH );
		if ( hash_equals( $expected, $nonce ) ) {
			return 2;
		}

		// Invalid nonce
		return false;
	}
endif;

if ( ! function_exists( 'wp_create_nonce' ) ) :
	function wp_create_nonce( $action = -1 ) {
		/* From core */
		$user = wp_get_current_user();
		$uid = (int) $user->ID;
		if ( ! $uid ) {
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		$token = wp_get_session_token();
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
		for( $i = 0; $i < $BBA_REPEATER; $i++ ) {
			$_rand .= dechex( rand( 16, 255 ) );
		}
		// Create the nonce with $_rand, this is the trick
		$nonce = substr( wp_hash( $wp_nonce_tick . '|' . $action . '|' . $uid . '|' . $token . '|' . $_rand, 'nonce' ), 0, $BBA_NONCE_LENGTH );
		// We had the rand into the string
		$nonce .= $_rand;
		// Obfuscate with XOR
		for( $i = 0; $i < strlen( $nonce ); $i++ ) {
            $nonce{ $i } = $nonce{ $i } ^ $NONCE_SALT{ $i % BBA_NONCE_LENGTH };
        }
        // Get a friendly nonce
        $nonce = bin2hex( $nonce );

		return $nonce;
	}
endif;

add_action( 'admin_footer', 'bba_add_dynamic_content' );
add_action( 'wp_footer', 'bba_add_dynamic_content' );
function bba_add_dynamic_content() {
	$md5 = md5( microtime( true ) );
	$repeat = str_repeat( chr( rand( 33, 126 ) ), (int) rand( 1, 32 ) );
	echo '<span style="display:none">' . $md5 . $repeat . '</span>';
}

if ( ! function_exists( 'baw_nonce_user_logged_out' ) ):
	add_filter( 'nonce_user_logged_out', 'baw_nonce_user_logged_out' );
	function baw_nonce_user_logged_out() {
		return md5( baw_get_ip() );
	}
endif;

if ( ! function_exists( 'baw_get_ip' ) ):
	function baw_get_ip() {
	    foreach ( array(
	             'HTTP_CLIENT_IP', 
	             'HTTP_X_FORWARDED_FOR', 
	             'HTTP_X_FORWARDED', 
	             'HTTP_X_CLUSTER_CLIENT_IP', 
	             'HTTP_FORWARDED_FOR', 
	             'HTTP_FORWARDED', 
	             'REMOTE_ADDR' ) as $key ) {
	        if ( array_key_exists( $key, $_SERVER ) ) {
	            $ip = explode( ',', $_SERVER[ $key ] );
	            $ip = end( $ip );
	            if ( filter_var( $ip, FILTER_VALIDATE_IP ) !== false ) {
	                return apply_filters( 'baw_get_ip', $ip );
	            }
	        }
	    }
	    return apply_filters( 'secupress_default_ip', '0.0.0.0' );
	}
endif;