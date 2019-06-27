<?php

/**
 * Plugin Name: WP-DevOps
 * Description: Run development operations via Javascript.  
 * Author: Juan Pablo Juliao
 * Author URI: jpjuliao.com
 * Version: 1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class Jpjuliao_WP_DevOps
{
    public $root;

    public function __construct()
    {
		$this->root = plugin_dir_path(__FILE__).'/../../';
        add_action('wp_ajax_devops', [$this, 'init']);
        add_action('wp_head', [$this, 'js_variables']);
    }
        
    public function init()
    {
        if (empty($_POST)) {
            echo 'Please enter parameters.';
            wp_die();
		}
		
        if (empty($_POST['action'])) {
            echo 'Please enter an action.';
            wp_die();
		}
		
        if ($_POST['action'] == 'git pull') {
            $this->git_pull();
		} 
		else {
            echo 'Please enter a valid action.';
		}
		
        wp_die();
    }

    public function js_variables() { ?>
        <script type="text/javascript">
          var ajaxurl = '<?php echo admin_url( "admin-ajax.php" ); ?>';
          var ajaxnonce = '<?php echo wp_create_nonce( "wp_devops_ajax_nonce" ); ?>';
        </script><?php
    }
        
    private function git_pull()
    {
        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
		}
		
        if (empty($_POST['login'])) {
            echo 'Please enter login parameter.';
			wp_die();
		}

        exec('cd '.$this->root.$_POST['repo']);
		$url = exec('git config --get remote.origin.url');
		if (!filter_var($url, FILTER_VALIDATE_URL)) {
            echo 'Remote origin URL not found.';
            wp_die();
		}
		
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (strpos($url, '@') !== false) {
            $url = $scheme.'://'.$_POST['login'].explode('@', $url)[1];
		} 
		else {
            $url = str_replace($scheme, $scheme.'://'.$_POST['login'].'@', $url);
		}
		
        echo exec('git pull '.$url);
        wp_die();
    }
}

new Jpjuliao_WP_DevOps();
