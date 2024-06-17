<?php
defined('ABSPATH') || die;

/*
Plugin Name: WPU htaccess Protect
Plugin URI: https://github.com/WordPressUtilities/wpuhtaccessprotect
Update URI: https://github.com/WordPressUtilities/wpuhtaccessprotect
Description: Replicate htaccess admin protection on some files
Version: 0.2.2
Author: Darklg
Author URI: https://darklg.me/
Text Domain: wpuhtaccessprotect
Requires at least: 6.2
Requires PHP: 8.0
Network: True
License: MIT License
License URI: https://opensource.org/licenses/MIT
*/

class wpuhtaccessprotect {
    private $plugin_version = '0.2.2';
    private $htpasswd_path = false;
    private $htaccess_authname = false;
    private $protected_files = array(
        'wp-activate.php',
        'wp-cron.php',
        'wp-login.php',
        'xmlrpc.php'
    );

    public function __construct() {
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
        if (!$this->check_htaccess_admin()) {
            return $rules;
        }

        $new_rules = '';
        $files = apply_filters('wpuhtaccessprotect__files', $this->protected_files);
        foreach ($files as $file) {
            $new_rules_part = array();
            $new_rules_part[] = '<Files ' . $file . '>';
            $new_rules_part[] = 'AuthType Basic';
            $new_rules_part[] = 'AuthName "' . $this->htaccess_authname . '"';
            $new_rules_part[] = 'AuthUserFile ' . $this->htpasswd_path . '';
            $new_rules_part[] = 'Require valid-user';
            $new_rules_part[] = '</Files>';
            $new_rules .= implode("\n", $new_rules_part) . "\n";
        }
        $signature_id = "WPU .htaccess Protect";
        $signature = $signature_id . " v" . $this->plugin_version . "\n";
        return
            "\n" .
            "# BEGIN " . $signature .
            $new_rules .
            "# END " . $signature_id .
            "\n" .
            $rules;

    }
}

$wpuhtaccessprotect = new wpuhtaccessprotect();

if (defined('WP_CLI') && WP_CLI) {
    WP_CLI::add_command('wpu-htaccess-protect-dump', function ($args = array()) {
        $wpuhtaccessprotect = new wpuhtaccessprotect();
        echo $wpuhtaccessprotect->rewrite_rules('');
    }, array(
        'shortdesc' => 'Dump WPU Htaccess protect rules',
        'synopsis' => array()
    ));
    WP_CLI::add_command('wpu-htaccess-protect-update-rules', function ($args = array()) {
        $wpuhtaccessprotect = new wpuhtaccessprotect();
        $new_rules = $wpuhtaccessprotect->rewrite_rules('');
        if (!$new_rules) {
            WP_CLI::error('No rules are available');
        }
        $ht = ABSPATH . '/.htaccess';
        if (!is_readable($ht)) {
            WP_CLI::error('htaccess file is not available');
        }
        $ht_content = file_get_contents($ht);

        preg_match('/# BEGIN WPU .htaccess Protect(.*)# END WPU .htaccess Protect/isU', $ht_content, $matches);
        if (!isset($matches[0]) || !$matches[0]) {
            WP_CLI::error('htaccess file does not contains the rules');
        }
        $ht_content = str_replace($matches[0], $new_rules, $ht_content);
        file_put_contents($ht, $ht_content);
        WP_CLI::success('Rules have been updated');

    }, array(
        'shortdesc' => 'Update WPU Htaccess protect rules directly in the .htaccess file',
        'synopsis' => array()
    ));
}
