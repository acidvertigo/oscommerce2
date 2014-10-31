<?php

/*
  $Id$

  osCommerce, Open Source E-Commerce Solutions
  http://www.oscommerce.com

  Copyright (c) 2014 osCommerce

  Released under the GNU General Public License
*/

class sessionshandler
{

  var $session_started = false;
  var $SID = '';
  
  public function __construct() {
      // set SID once, even if empty
      $this->SID = (defined('SID') ? SID : '');
      $this->session_set();
  }

  function session_start() {

    if (SESSION_FORCE_COOKIE_USE == 'True') {
        $this->session_cookie();
      } elseif (SESSION_BLOCK_SPIDERS == 'True') {
        
        $user_agent = '';
        
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
         $user_agent = strtolower($_SERVER['HTTP_USER_AGENT']);
        }

        $spider_flag = false;
        
        if (!empty($user_agent)) {
            foreach (file('includes/spiders.txt') as $spider) {
              if (!empty($spider)) {
                if (strpos($user_agent, $spider) !== false) {
                  $spider_flag = true;
                    break;
                }
              }
            }
        }

        if ($spider_flag === false) {
            tep_session_start();
            $this->session_started = true;
        }
        
      } else {
          tep_session_start();
          $this->session_started = true;
      }
      
      
    }

    function session_cookie(){
        tep_setcookie('cookie_test', 'please_accept_for_session', time() + 60 * 60 * 24 * 30);

      if (isset($_COOKIE['cookie_test'])) {
        tep_session_start();
        $this->session_started = true;
      }
    }

  function session_set() {
    global $request_type;
      
    // set the session name and save path
    session_name('osCsid');
    session_save_path(SESSION_WRITE_DIRECTORY);
        
    if ($request_type = 'SSL') {
      // set the cookie domain
      $cookie_domain = HTTPS_COOKIE_DOMAIN;
      $cookie_path = HTTPS_COOKIE_PATH;
    } else {
      // set the cookie domain
      $cookie_domain = HTTP_COOKIE_DOMAIN;
      $cookie_path = HTTP_COOKIE_PATH;
    }
        
    // set the session cookie parameters
    session_set_cookie_params(0, $cookie_path, $cookie_domain);

    if (function_exists('ini_set')) {
      ini_set('session.use_only_cookies', (SESSION_FORCE_COOKIE_USE == 'True') ? 1 : 0);
    }

    // set the session ID if it exists
    if (SESSION_FORCE_COOKIE_USE == 'False') {
      if (isset($_GET[session_name()]) && (!isset($_COOKIE[session_name()]) || ($_COOKIE[session_name()] != $_GET[session_name()]))) {
        session_id($_GET[session_name()]);
      } elseif (isset($_POST[session_name()]) && (!isset($_COOKIE[session_name()]) || ($_COOKIE[session_name()] != $_POST[session_name()]))) {
        session_id($_POST[session_name()]);
      }
    }
  
  // initialize a session token
    if (!isset($_SESSION['sessiontoken'])) {
      $this->create_token();
    }

    // verify the browser user agent if the feature is enabled
    if (SESSION_CHECK_USER_AGENT == 'True') {
        $this->verify_user_agent();
    }

    // verify the IP address if the feature is enabled
    if (SESSION_CHECK_IP_ADDRESS == 'True') {
       $this->verify_ip_address();
    }
    
    if (($request_type == 'SSL') && (SESSION_CHECK_SSL_SESSION_ID == 'True') && (ENABLE_SSL == true) && ($this->session_started === true)) {
      $this->verify_ssl($request_type);
    }
    
   
  }

  function create_token() {
    $_SESSION['sessiontoken'] = md5(tep_rand().tep_rand().tep_rand().tep_rand());
  }

  function verify_ssl($request_type) {
      
    // verify the ssl_session_id if the feature is enabled
      if (!isset($_SESSION['SSL_SESSION_ID'])) {
        $_SESSION['SESSION_SSL_ID'] = $_SERVER['SSL_SESSION_ID'];
      }

      if ($_SESSION['SESSION_SSL_ID'] != $_SERVER['SSL_SESSION_ID']) {
        tep_session_destroy();
        tep_redirect(tep_href_link(FILENAME_SSL_CHECK));
      }
    
  }

  function verify_user_agent() {
    if (!isset($_SESSION['SESSION_USER_AGENT'])) {
      $_SESSION['SESSION_USER_AGENT'] = $_SERVER['HTTP_USER_AGENT'];
    }

    if ($_SESSION['SESSION_USER_AGENT'] != $_SERVER['HTTP_USER_AGENT']) {
      tep_session_destroy();
      tep_redirect(tep_href_link(FILENAME_LOGIN));
    }
  }

  function verify_ip_address() {
    if (!isset($_SESSION['SESSION_IP_ADDRESS'])) {
      $_SESSION['SESSION_IP_ADDRESS'] = tep_get_ip_address();
    }

    if ($_SESSION['SESSION_IP_ADDRESS'] != tep_get_ip_address()) {
      tep_session_destroy();
      tep_redirect(tep_href_link(FILENAME_LOGIN));
    }
  }

}
