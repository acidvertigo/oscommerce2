<?php
/*
  $Id$

  osCommerce, Open Source E-Commerce Solutions
  http://www.oscommerce.com

  Copyright (c) 2010 osCommerce

  Released under the GNU General Public License
*/

  $login_request = true;

  require('includes/application_top.php');
  require('includes/functions/password_funcs.php');

  $action = (isset($_GET['action']) ? $_GET['action'] : '');

// prepare to logout an active administrator if the login page is accessed again
  if (isset($_SESSION['admin'])) {
    $action = 'logoff';
  }

  if (osc_not_null($action)) {
    switch ($action) {
      case 'process':
        if (isset($_SESSION['redirect_origin']) && isset($_SESSION['redirect_origin']['auth_user'])) {
          $username = osc_db_prepare_input($_SESSION['redirect_origin']['auth_user']);
          $password = osc_db_prepare_input($_SESSION['redirect_origin']['auth_pw']);
        } else {
          $username = osc_db_prepare_input($_POST['username']);
          $password = osc_db_prepare_input($_POST['password']);
        }

        $actionRecorder = new actionRecorderAdmin('ar_admin_login', null, $username);

        if ($actionRecorder->canPerform()) {
          $check_query = osc_db_query("select id, user_name, user_password from " . TABLE_ADMINISTRATORS . " where user_name = '" . osc_db_input($username) . "'");

          if (osc_db_num_rows($check_query) == 1) {
            $check = osc_db_fetch_array($check_query);

            if (osc_validate_password($password, $check['user_password'])) {
// migrate old hashed password to new phpass password
              if (osc_password_type($check['user_password']) != 'phpass') {
                osc_db_query("update " . TABLE_ADMINISTRATORS . " set user_password = '" . osc_encrypt_password($password) . "' where id = '" . (int)$check['id'] . "'");
              }

              $_SESSION['admin'] = array('id' => $check['id'],
                                         'username' => $check['user_name']);

              $actionRecorder->_user_id = $_SESSION['admin']['id'];
              $actionRecorder->record();

              if (isset($_SESSION['redirect_origin'])) {
                $page = $_SESSION['redirect_origin']['page'];
                $get_string = http_build_query($_SESSION['redirect_origin']['get']);

                unset($_SESSION['redirect_origin']);

                osc_redirect(osc_href_link($page, $get_string));
              } else {
                osc_redirect(osc_href_link(FILENAME_DEFAULT));
              }
            }
          }

          $messageStack->add(ERROR_INVALID_ADMINISTRATOR, 'error');
        } else {
          $messageStack->add(sprintf(ERROR_ACTION_RECORDER, (defined('MODULE_ACTION_RECORDER_ADMIN_LOGIN_MINUTES') ? (int)MODULE_ACTION_RECORDER_ADMIN_LOGIN_MINUTES : 5)));
        }

        $actionRecorder->record(false);

        break;

      case 'logoff':
        unset($_SESSION['admin']);

        if (isset($_SERVER['PHP_AUTH_USER']) && !empty($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']) && !empty($_SERVER['PHP_AUTH_PW'])) {
          $_SESSION['auth_ignore'] = true;
        }

        osc_redirect(osc_href_link(FILENAME_DEFAULT));

        break;

      case 'create':
        $check_query = osc_db_query("select id from " . TABLE_ADMINISTRATORS . " limit 1");

        if (osc_db_num_rows($check_query) == 0) {
          $username = osc_db_prepare_input($_POST['username']);
          $password = osc_db_prepare_input($_POST['password']);

          osc_db_query("insert into " . TABLE_ADMINISTRATORS . " (user_name, user_password) values ('" . osc_db_input($username) . "', '" . osc_db_input(osc_encrypt_password($password)) . "')");
        }

        osc_redirect(osc_href_link(FILENAME_LOGIN));

        break;
    }
  }

  $languages = osc_get_languages();
  $languages_array = array();
  $languages_selected = DEFAULT_LANGUAGE;
  for ($i = 0, $n = sizeof($languages); $i < $n; $i++) {
    $languages_array[] = array('id' => $languages[$i]['code'],
                               'text' => $languages[$i]['name']);
    if ($languages[$i]['directory'] == $_SESSION['language']) {
      $languages_selected = $languages[$i]['code'];
    }
  }

  $admins_check_query = osc_db_query("select id from " . TABLE_ADMINISTRATORS . " limit 1");
  if (osc_db_num_rows($admins_check_query) < 1) {
    $messageStack->add(TEXT_CREATE_FIRST_ADMINISTRATOR, 'warning');
  }

  require(DIR_WS_INCLUDES . 'template_top.php');
?>

<table border="0" width="100%" cellspacing="2" cellpadding="2">
  <tr>
    <td><table border="0" width="100%" cellspacing="0" cellpadding="0" height="40">
      <tr>
        <td class="pageHeading"><?php echo HEADING_TITLE; ?></td>

<?php
  if (sizeof($languages_array) > 1) {
?>

        <td class="pageHeading" align="right"><?php echo osc_draw_form('adminlanguage', FILENAME_DEFAULT, '', 'get') . osc_draw_pull_down_menu('language', $languages_array, $languages_selected, 'onchange="this.form.submit();"') . osc_hide_session_id() . '</form>'; ?></td>

<?php
  }
?>

      </tr>
    </table></td>
  </tr>
  <tr>
    <td>

<?php
  $heading = array();
  $contents = array();

  if (osc_db_num_rows($admins_check_query) > 0) {
    $heading[] = array('text' => '<strong>' . HEADING_TITLE . '</strong>');

    $contents = array('form' => osc_draw_form('login', FILENAME_LOGIN, 'action=process'));
    $contents[] = array('text' => TEXT_USERNAME . '<br />' . osc_draw_input_field('username'));
    $contents[] = array('text' => '<br />' . TEXT_PASSWORD . '<br />' . osc_draw_password_field('password'));
    $contents[] = array('align' => 'center', 'text' => '<br />' . osc_draw_button(BUTTON_LOGIN, 'key'));
  } else {
    $heading[] = array('text' => '<strong>' . HEADING_TITLE . '</strong>');

    $contents = array('form' => osc_draw_form('login', FILENAME_LOGIN, 'action=create'));
    $contents[] = array('text' => TEXT_CREATE_FIRST_ADMINISTRATOR);
    $contents[] = array('text' => '<br />' . TEXT_USERNAME . '<br />' . osc_draw_input_field('username'));
    $contents[] = array('text' => '<br />' . TEXT_PASSWORD . '<br />' . osc_draw_password_field('password'));
    $contents[] = array('align' => 'center', 'text' => '<br />' . osc_draw_button(BUTTON_CREATE_ADMINISTRATOR, 'key'));
  }

  $box = new box;
  echo $box->infoBox($heading, $contents);
?>

    </td>
  </tr>
</table>

<?php
  require(DIR_WS_INCLUDES . 'template_bottom.php');
  require(DIR_WS_INCLUDES . 'application_bottom.php');
?>
