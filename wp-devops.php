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
        add_action('wp_head', [$this, 'js']);
        add_action('admin_head', [$this, 'js']);
    }
        
    public function init()
    {
        if (current_user_can('manage_options')) {
            echo 'User not allowed.';
            wp_die();
        }

        if (empty($_POST)) {
            echo 'Please enter parameters.';
            wp_die();
		}
		
        if (empty($_POST['action'])) {
            echo 'Please enter an action.';
            wp_die();
		}
        
        switch ($_POST['git']) {
            case 'pull'     : $this->git_pull(); break;
            case 'status'   : $this->git_status(); break;
            default         : echo 'Please enter a valid git command.';
        }
		
        wp_die();
    }

    public function js() { ?>
        <script type="text/javascript">
            function devops($params) {
                'use strict';
                jQuery.post(
                    <?php echo admin_url( "admin-ajax.php" ); ?>, 
                    $params, 
                    function(response) {
                        console.log('WP-Devops: ', response);
                    }
                );
            }
        </script><?php
    }
        
    private function git_pull()
    {
        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
        }
        
        if (empty($_POST['branch'])) {
            echo 'Please enter branch parameter.';
            wp_die();
		}
		
        if (empty($_POST['login'])) {
            echo 'Please enter login parameter.';
			wp_die();
		}

        $dir = 'cd '.$this->root.$_POST['repo'];
        $url = exec($dir.'; git config --get remote.origin.url');
		if (!filter_var($url, FILTER_VALIDATE_URL)) {
            echo 'Remote origin URL not found.';
            wp_die();
		}
		
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (strpos($url, '@') !== false) {
            $url = $scheme.
                '://'.$_POST['login'].
                explode('@', $url)[1];
		} 
		else {
            $url = str_replace(
                $scheme.'://', 
                $scheme.'://'.$_POST['login'].'@', $url
            );
        }
        
        $output = [];
        exec($dir.'; git pull '.$url.' '.$_POST['branch'], $output);
        echo implode('\n', $output);
        wp_die();
    }

    private function git_status() {
        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
        }
        
        $output = [];
        $dir = 'cd '.$this->root.$_POST['repo'];
        exec($dir.'; git status', $output);
        echo implode('\n', $output);
        wp_die();
    }
}

new Jpjuliao_WP_DevOps();
