<?php

/**
 * SQL Password Driver
 *
 * Driver for passwords stored in SQL database
 *
 * @version 1.4
 * @author Ignacio Nieto Carvajal <contact@digitalleaves.com>
 *
 */

define (DB_HOST, 'your host');
define (DB_USER, 'your host');
define (DB_PASSWORD, 'your host');
define (DB_NAME, 'your host');

function password_save($curpass, $passwd)
{
    $rcmail = rcmail::get_instance();

    if (!($sql = $rcmail->config->get('password_query')))
        $sql = 'SELECT update_passwd(%c, %u)';

	$db = mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
   if ($db == false) return PASSWORD_ERROR;

    // crypted password
    if (strpos($sql, '%c') !== FALSE) {
        $salt = '';
        if (CRYPT_MD5) {
            // Always use eight salt characters for MD5 (#1488136)
    	    $len = 8;
        } else if (CRYPT_STD_DES) {
    	    $len = 2;
        } else {
    	    return PASSWORD_CRYPT_ERROR;
        }

        //Restrict the character set used as salt (#1488136)
        $seedchars = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        for ($i = 0; $i < $len ; $i++) {
    	    $salt .= $seedchars[rand(0, 63)];
        }

        $sql = str_replace('%c',  $db->real_escape_string(crypt($passwd, CRYPT_MD5 ? '$1$'.$salt.'$' : $salt)), $sql);
    }

    // dovecotpw
    if (strpos($sql, '%D') !== FALSE) {
        if (!($dovecotpw = $rcmail->config->get('password_dovecotpw')))
            $dovecotpw = 'dovecotpw';
        if (!($method = $rcmail->config->get('password_dovecotpw_method')))
            $method = 'CRAM-MD5';

        // use common temp dir
        $tmp_dir = $rcmail->config->get('temp_dir');
        $tmpfile = tempnam($tmp_dir, 'roundcube-');

        $pipe = popen("$dovecotpw -s '$method' > '$tmpfile'", "w");
        if (!$pipe) {
            unlink($tmpfile);
            return PASSWORD_CRYPT_ERROR;
        }
        else {
            fwrite($pipe, $passwd . "\n", 1+strlen($passwd)); usleep(1000);
            fwrite($pipe, $passwd . "\n", 1+strlen($passwd));
            pclose($pipe);
            $newpass = trim(file_get_contents($tmpfile), "\n");
            if (!preg_match('/^\{' . $method . '\}/', $newpass)) {
                return PASSWORD_CRYPT_ERROR;
            }
            if (!$rcmail->config->get('password_dovecotpw_with_method'))
                $newpass = trim(str_replace('{' . $method . '}', '', $newpass));
            unlink($tmpfile);
        }
        $sql = str_replace('%D', $db->real_escape_string($newpass), $sql);
    }

    // hashed passwords
    if (preg_match('/%[n|q]/', $sql)) {

	    if (!extension_loaded('hash')) {
	        raise_error(array(
	            'code' => 600,
		        'type' => 'php',
		        'file' => __FILE__, 'line' => __LINE__,
		        'message' => "Password plugin: 'hash' extension not loaded!"
		    ), true, false);

	        return PASSWORD_ERROR;
	    }

	    if (!($hash_algo = strtolower($rcmail->config->get('password_hash_algorithm'))))
            $hash_algo = 'sha1';

	    $hash_passwd = hash($hash_algo, $passwd);
        $hash_curpass = hash($hash_algo, $curpass);

	    if ($rcmail->config->get('password_hash_base64')) {
            $hash_passwd = base64_encode(pack('H*', $hash_passwd));
            $hash_curpass = base64_encode(pack('H*', $hash_curpass));
        }

	    $sql = str_replace('%n', $db->real_escape_string($hash_passwd, 'text'), $sql);
	    $sql = str_replace('%q', $db->real_escape_string($hash_curpass, 'text'), $sql);
    }

    $local_part  = $rcmail->user->get_username('local');
    $domain_part = $rcmail->user->get_username('domain');
    $username    = $_SESSION['username'];
    $host        = $_SESSION['imap_host'];

    // convert domains to/from punnycode
    if ($rcmail->config->get('password_idn_ascii')) {
        $domain_part = rcube_idn_to_ascii($domain_part);
        $username    = rcube_idn_to_ascii($username);
        $host        = rcube_idn_to_ascii($host);
    }
    else {
        $domain_part = rcube_idn_to_utf8($domain_part);
        $username    = rcube_idn_to_utf8($username);
        $host        = rcube_idn_to_utf8($host);
    }

    // at least we should always have the local part
    $sql = str_replace('%l', $db->real_escape_string($local_part), $sql);
    $sql = str_replace('%d', $db->real_escape_string($domain_part), $sql);
    $sql = str_replace('%u', $db->real_escape_string($username), $sql);
    $sql = str_replace('%h', $db->real_escape_string($host), $sql);
    $sql = str_replace('%p', $db->real_escape_string($passwd), $sql);
    $sql = str_replace('%o', $db->real_escape_string($curpass), $sql);

	error_log("Cambiando la contraseña de $username a $curpass");
	$res = $db->query($sql);
	if ($res == false) {
		return PASSWORD_ERROR;
	} else {
		return PASSWORD_SUCCESS;
	}
}

?>
