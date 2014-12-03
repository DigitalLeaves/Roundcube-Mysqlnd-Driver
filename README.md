Roundcube-Mysqlnd-Driver
========================

A driver for roundcube 0.7 if you happen to have Mysqlnd installed instead of Mysql in your Linux/Unix box, and thus, due to debian dependencies, you are unable to install Mysql and use the old PDO methods for accessing the database.

Versioning
==========
This file is compatible with the last stable version available for Debian, concretely Roundcube v7.x.

Install
=======
This instructions imply that you have already installed and configured the password roundcube plugin to your needs.
 
1. Add driver file sqli.php to your roundcube_install_dir/plugins/password/drivers/
2. Edit sqli.php and set the database values DB_HOST, DB_USER, DB_PASSWORD and DB_NAME.
3. Edit your config.inc.php file at roundcube_install_dir/plugins/password/ and set the driver option to sqli:

```
$rcmail_config['password_driver'] = 'sqli';
```

4. Make sure you have the "password" plugin properly added at your roundcube config file: roundcube_install_dir/config/main.inc.php

```
$rcmail_config['plugins'] = array('password');
```

Please note: the official documentation seems to imply that "password" can be written without the quotation marks. I had some trouble until I did include them.

Custom Update Password Query
============================
The sqli driver supports custom update queries, with the usual roundcube password modifiers:

* %p is replaced with the plaintext new password
* %c is replaced with the crypt version of the new password, MD5 if available, otherwise DES.
* %D is replaced with the dovecotpw-crypted version of the new password
* %o is replaced with the password before the change
* %n is replaced with the hashed version of the new password
* %q is replaced with the hashed password before the change
* %h is replaced with the imap host (from the session info)
* %u is replaced with the username (from the session info)
* %l is replaced with the local part of the username (in case the username is an email address)
* %d is replaced with the domain part of the username (in case the username is an email address)

You could, for example, use the following query:
```
$rcmail_config['password_query'] = 'UPDATE users SET password=ENCRYPT(\'%p\', CONCAT("$6$", SUBSTRING(SHA(RAND()), -16))) WHERE username=\'%u\' LIMIT 1';
```

