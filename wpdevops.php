<?php

/**
 * Plugin Name: WPDevOps
 * Description: Run useful development operations.
 * Author: Juan Pablo Juliao
 * Author URI: jpjuliao.com
 * Version: 1.0
 */

Namespace JPJuliao\Wordpress;

if (!defined('ABSPATH')) {
    exit;
}

new DevOps();

class DevOps {

    public $root;

    public function __construct() {
		$this->root = plugin_dir_path(__FILE__).'../../';
        add_action('wp_ajax_devops', [$this, 'controller']);
        add_action('wp_head', [$this, 'js']);
        add_action('admin_head', [$this, 'js']);
        add_action('admin_menu', [$this, 'register_sub_menu']);
        add_action('current_screen', [$this, 'shell_page']);
    }
    
    public function register_sub_menu() {
        add_submenu_page( 
            'tools.php', 
            'DevOps', 
            'DevOps', 
            'manage_options', 
            'devops', 
            [$this, 'submenu_page_callback']
        );
    }

    public function submenu_page_callback() { 
        ?>
        <div class="wrap">
            <h2>DevOps</h2>
            <button class="option-shell">Shell</button>
        </div>
        <script>
            (function(){
                'use strict';
                jQuery(document).ready(function($){
                    $('.option-shell').click(function(){
                        window.open(
                            "<?php menu_page_url('devops') ?>&option=shell", 
                            "DevOps Shell", 
                            "menubar=no,location=no,resizable=yes,scrollbars=yes,status=yes"
                        );
                    });
                });
            })()
        </script>
        <?php 
    }

    public function shell_page() {
        if (isset($_GET['option'])) {
            if ($_GET['option'] == 'shell') {
                include 'shell/shell.php';
                die;
            }
        }
    }
        
    public function controller() {
        if (!current_user_can('manage_options')) {
            echo 'User not allowed.';
            wp_die();
        }

        if (empty($_POST)) {
            echo 'Please enter parameters. More info: https://github.com/jpjuliao/wpdevops';
            wp_die();
        }
        
        if (isset($_POST['update'])) {
            $this->update();
            wp_die();
        }
        
        if (!empty($_POST['git'])) {
            switch ($_POST['git']) {
                case 'config': $this->git_config(); break;
                case 'pull': $this->git_pull(); break;
                case 'status': $this->git_status(); break;
                default: echo 'Please enter a valid git command.';
            }
            wp_die();
        }
        
        if (!empty($_POST['db'])) {
            switch ($_POST['db']) {
                case 'get_results': $this->db_get_results(); break;
                default: echo 'Please enter a valid $wpdb command.';
            }
            wp_die();
        }
        
        if (!empty($_POST['cmd'])) {
            $this->shell($_POST['cmd']);
            wp_die();
        }
        
        if (!empty($_POST['file'])) {
            $this->upload($_POST['file']);
            wp_die();
        }

        echo 'More info: https://github.com/jpjuliao/wpdevops';
        wp_die();
		
    }

    public function js() { ?>
        <script type="text/javascript">
            (function(){
                'use strict';
                window.devops = (params = {}) => {
                    if (params == 'update') {
                        params = {update:true};
                    }
                    params.action = 'devops';
                    jQuery.ajax({
                        url: '<?php echo admin_url( "admin-ajax.php" ); ?>',
                        method: "POST",
                        data: params, 
                        contentType: "application/json; charset=utf-8",
                        dataType: "json",
                        success: function(response) {
                            console.log('# DevOps Response: ');
                            let responseJSON = tryParseJSON(response);
                            if (responseJSON) {
                                console.log(responseJSON);
                            }
                            else {
                                console.log(response);
                            }
                        }
                    });
                    function tryParseJSON(jsonString) {
                        try {
                            let o = JSON.parse(jsonString);
                            if (o && typeof o === "object") {
                                return o;
                            }
                        }
                        catch (e) { }
                        return false;
                    };
                }
            })();
        </script><?php
    }

    private function update() {
        $output = [];
        exec('cd '.$this->root.'plugins/wpdevops; git pull', $output);
        foreach($output as $line) echo $line.PHP_EOL;
        wp_die();
    }

    private function shell() {
        if (isset($_POST['cmd'])) {
            $output = preg_split('/[\n]/', shell_exec($_POST['cmd']." 2>&1"));
            foreach ($output as $line) {
                echo htmlentities($line, ENT_QUOTES | ENT_HTML5, 'UTF-8') . "<br>";
            }
            wp_die(); 
        } 
    }
    
    private function upload() {
        if (!empty($_FILES['file']['tmp_name']) && !empty($_POST['path'])) {
            $filename = $_FILES["file"]["name"];
            $path = $_POST['path'];
            if ($path != "/") {
                $path .= "/";
            } 
            if (move_uploaded_file($_FILES["file"]["tmp_name"], $path.$filename)) {
                echo htmlentities($filename) . " successfully uploaded to " . htmlentities($path);
            } else {
                echo "Error uploading " . htmlentities($filename);
            }
            wp_die();
        }
    }

    private function git_config() {

        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
        }

        $dir = $this->root.$_POST['repo'];
        $config_file = $dir.'/.git/config';
        if (!file_exists($config_file)) {
            echo 'Git config file not found.';
            wp_die();
        }
        $file = file($config_file);
            
        foreach($file as $line) echo $line;
        wp_die();
    
    } 
        
    private function git_pull() {

        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
        }

        $dir = $this->root.$_POST['repo'];
        $url = exec('cd '.$dir.'; git config --get remote.origin.url');
		if (!filter_var($url, FILTER_VALIDATE_URL)) {
            echo 'Remote origin URL not found.';
            wp_die();
		}
		
        if (!empty($_POST['login'])) {
            $scheme = parse_url($url, PHP_URL_SCHEME);
            if (strpos($url, '@') !== false) {
                $url = $scheme.
                    '://'.$_POST['login'].
                    explode('@', $url)[1];
            } else {
                $url = str_replace(
                    $scheme.'://',
                    $scheme.'://'.$_POST['login'].'@',
                    $url
                );
            }
        }
        
        $command = 'cd '.$dir.'; git pull '.$url.
            (isset($_POST['branch']) ? ' '.$_POST['branch'] : '');
            
        $output = [];
        exec($command, $output);
        foreach($output as $line) echo $line.PHP_EOL;
        wp_die();
    }

    private function git_status() {
        if (empty($_POST['repo'])) {
            echo 'Please enter repo parameter.';
            wp_die();
        }
        
        $command = 'cd '.$this->root.$_POST['repo'].
            '; git status';
        
        $output = [];
        exec($command, $output);
        foreach($output as $line) echo $line.PHP_EOL;
        wp_die();
    }

    private function git_clone() {
        // Todo
    }

    private function db_get_results() {
        if (empty($_POST['query'])) {
            echo "Please enter query parameter";
            wp_die();
        }
        global $wpdb;
        $query = stripslashes($_POST['query']);
        $results = $wpdb->get_results($query);
        echo json_encode($results);
        wp_die();
    }

}

