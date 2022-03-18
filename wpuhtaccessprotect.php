<?php

/*
Plugin Name: WPU htaccess Protect
Plugin URI: https://github.com/WordPressUtilities/wpuhtaccessprotect
Description: Replicate htaccess admin protection on some files
Version: 0.1.0
Author: Darklg
Author URI: https://darklg.me/
License: MIT License
License URI: https://opensource.org/licenses/MIT
*/

class wpuhtaccessprotect {
    private $plugin_version = '0.1.0';
    private $htpasswd_path = false;
    private $htaccess_authname = false;
    private $protected_files = array(
        'wp-activate.php',
        'wp-cron.php',
        'wp-login.php',
        'xmlrpc.php'
    );

    public function __construct() {
        if (!$this->check_htaccess_admin()) {
            return;
        }
        add_filter('mod_rewrite_rules', array(&$this, 'rewrite_rules'), 10, 1);
    }

    public function check_htaccess_admin() {
        $htaccess_file = ABSPATH . '/wp-admin/.htaccess';
        /* Check if htaccess file exists */
        if (!file_exists($htaccess_file)) {
            return false;
        }
        $htaccess_file_content = file_get_contents($htaccess_file);
        /* Check if it contains an auth protection */
        if (strpos($htaccess_file_content, 'AuthType Basic') === false) {
            return false;
        }
        /* Extract AuthName */
        preg_match('/AuthName[ ]+"([^"]*)"/', $htaccess_file_content, $match_authname);
        if (!isset($match_authname[1])) {
            return;
        }
        $this->htaccess_authname = $match_authname[1];
        /* Extract AuthUserFile */
        preg_match('/AuthUserFile\s+(.*\.htpasswd)/isU', $htaccess_file_content, $match_authuserfile);
        if (!isset($match_authuserfile[1])) {
            return;
        }
        $this->htpasswd_path = $match_authuserfile[1];

        return true;
    }

    public function rewrite_rules($rules) {
        $new_rules = '';

        foreach ($this->protected_files as $file) {
            $new_rules_part = array();
            $new_rules_part[] = '<Files ' . $file . '>';
            $new_rules_part[] = 'AuthType Basic';
            $new_rules_part[] = 'AuthName "' . $this->htaccess_authname . '"';
            $new_rules_part[] = 'AuthUserFile ' . $this->htpasswd_path . '';
            $new_rules_part[] = 'Require valid-user';
            $new_rules_part[] = '</Files>';
            $new_rules .= implode("\n", $new_rules_part) . "\n";
        }
        $signature = "WPU .htaccess Protect v" . $this->plugin_version . "\n";
        return
            "# BEGIN " . $signature .
            $new_rules .
            "# END " . $signature .
            $rules;

    }
}

$wpuhtaccessprotect = new wpuhtaccessprotect();
