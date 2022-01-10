<?php
/**
 * Forgot Password
 *
 * Plugin to reset an account password
 *
 * @version 1.4
 * @original_author Fabio Perrella and Thiago Coutinho (Locaweb)
 * Contributing Author: Jerry Elmore
 * Edited for own purposes by: Samoilov Yuri
 * @url https://github.com/drlight/roundcube-forgot_password
 * Updated to work with roundcube 1.5: Bradley Jarvis
 * @url https://github.com/bradley-jarvis/roundcube-forgot_password
 */
class forgot_password extends rcube_plugin 
{
    public $task = 'login|logout|settings|mail';
    
    private $rc;
    
    function init()
    {
        define('TOKEN_EXPIRATION_TIME_MIN',20);
        
        $this->rc = rcmail::get_instance();
        $this->load_config();
        
        $this->add_texts('localization/');
        
        if ($this->rc->task == 'mail')
        {
            $this->add_hook('messages_list', array($this, 'show_warning_alternative_email'));
            $this->add_hook('render_page', array($this, 'add_labels_to_mail_page'));
        } else
        {
            if ($this->rc->task == 'settings')
            {
                if ($this->rc->action == 'plugin.password' ||
                    $this->rc->action == 'plugin.password-save-forgot_password')
                {
                    $this->add_hook('render_page', array($this, 'add_field_alternative_email_to_form'));
                }
                $this->register_action(
                    'plugin.password-save-forgot_password',
                    array($this, 'password_save'));
            } else
            {
                $this->include_script('js/forgot_password.js');
            }
            
            $this->add_hook('render_page', array($this, 'add_labels_to_login_page'));
            $this->load_config('config.inc.php');
            
            $this->add_hook('render_page', array($this, 'add_labels_to_login_page'));
            $this->add_hook('startup', array($this, 'forgot_password_reset'));
            $this->register_action(
                'plugin.forgot_password_reset',
                array($this, 'forgot_password_redirect'));
            
            $this->add_hook('startup', array($this, 'new_password_form'));
            $this->register_action(
                'plugin.new_password_form',
                array($this, 'new_password_form'));
            
            $this->add_hook('startup', array($this, 'new_password_do'));
            $this->register_action(
                'plugin.new_password_do',
                array($this, 'new_password_do'));
        }
    }
    
    function add_field_alternative_email_to_form()
    {
        $sql_result = $this->rc->db->query(
            'SELECT alternative_email FROM forgot_password ' .
            ' WHERE user_id = ? ', $this->rc->user->ID);
        $userrec = $this->rc->db->fetch_assoc($sql_result);
        $this->rc->output->add_script(
            '$(document).ready(function($){' .
            '$("#password-form table :first").prepend(\'' .
            '<tr class="alternative_email">' .
            '<td class="title"><label for="alternative_email">' .
            $this->gettext('recovery_email','forgot_password') .
            ':</label></td>' .
            '<td><input type="text" autocomplete="off" size="20" id="alternative_email" ' .
                'name="alternative_email" value="' . $userrec['alternative_email'] . '"></td>' .
            '</tr>\');' .
            'form_action = $("#password-form").attr("action");' .
            'form_action = form_action.replace("plugin.password-save",' .
                '"plugin.password-save-forgot_password");' .
            '$("#password-form").attr("action",form_action);' .
            '});');
        //disable password plugin's javascript validation
        $this->include_script('js/change_save_button.js');
    }
    
    function password_save()
    {
        $alternative_email = rcube_utils::get_input_value(
            'alternative_email',
            rcube_utils::INPUT_POST);
        
        if (preg_match('/.+@[^.]+\..+/Umi',$alternative_email))
        {
            $this->rc->db->query(
                "REPLACE INTO forgot_password(alternative_email, user_id) values(?,?)",
                $alternative_email, $this->rc->user->ID);
            
            $message = $this->gettext('alternative_email_updated','forgot_password');
            $this->rc->output->command('display_message', $message, 'confirmation');
        } else
        {
            $message = $this->gettext('alternative_email_invalid','forgot_password');
            $this->rc->output->command('display_message', $message, 'error');
        }
        //samoilov 02.05.2019 code below needs
        $password_plugin = new password($this->api);
        //if ($_REQUEST['_curpasswd'] || $_REQUEST['_newpasswd'] || $_REQUEST['_confpasswd'])
        if ($_REQUEST['_newpasswd'] || $_REQUEST['_confpasswd'])
        {
            $password_plugin->password_save();
        } else
        {
            //render password form
            $password_plugin->add_texts('localization/');
            $this->register_handler('plugin.body', array($password_plugin, 'password_form'));
            $this->rc->overwrite_action('plugin.password');
            $this->rc->output->send('plugin');
            //$this->rc->output->send('plugin.password');
        }
    }
    
    function show_warning_alternative_email()
    {
        $rcmail = rcmail::get_instance();
        $sql_result = $this->rc->db->query('SELECT alternative_email FROM forgot_password where user_id=?',$this->rc->user->ID);
        $userrec = $this->rc->db->fetch_assoc($sql_result);
        
        if (!$userrec['alternative_email'] &&
            !isset($_SESSION['show_warning_alternative_email']))
        {
            // JRE - SET THIS a href TO THE URL FOR YOUR RC login screen, e.g. https://your.domain.com/login
            $link = "<a href='/?_task=settings&_action=plugin.password'>" .
                $this->gettext('click_here','forgot_password') ."</a>";
            $message = sprintf($this->gettext('notice_no_alternative_email_warning','forgot_password'),$link);
            $this->rc->output->command('display_message', $message, 'notice');
            //samoilov 29.04.2019 comment line below to force warning of no alt email configured
            $_SESSION['show_warning_alternative_email'] = true;
        }
    }

    function new_password_do($a)
    {
        if($a['action'] != 'plugin.new_password_do' || !isset($_SESSION['temp']))
            return $a;
        
        $rcmail = rcmail::get_instance();
        
        $new_password = rcube_utils::get_input_value('new_password',rcube_utils::INPUT_POST);
        $new_password_confirmation = rcube_utils::get_input_value('new_password_confirmation',rcube_utils::INPUT_POST);
        $token = rcube_utils::get_input_value('_t',rcube_utils::INPUT_POST);
        // samoilov 28.04.2019 change sql query for update password
        
        if($new_password && $new_password == $new_password_confirmation)
        {
            // JRE - You will need to adjust table name to whatever table name you use for your users in roundcubedb
            /*    $this->rc->db->query("UPDATE ".$this->rc->db->table_name('users', true).
            " SET password=? " .
            " WHERE user_id=(SELECT user_id FROM forgot_password WHERE token=?)",
            array($this->rc->encrypt($new_password), $token)); */

            // samoilov 30.04.2019 $new_password check for weakness below
            // Validate password strength
            $uppercase = preg_match('@[A-Z]@', $new_password);
            $lowercase = preg_match('@[a-z]@', $new_password);
            $number    = preg_match('@[0-9]@', $new_password);
            $specialChars = preg_match('/[!|@|#|$|%|^|&|*|_|(|)]/', $new_password);
            if(!$uppercase || !$lowercase || !$number || !$specialChars || 
                strlen($new_password) < 7)
            {
                $message = $this->gettext('password_weakness_check_failed','forgot_password');
                $type = 'error';
                $this->rc->output->command('display_message', $message, $type);
                $this->rc->output->send('forgot_password.new_password_form');
            } else
            {
                $this->rc->db->query(
                    "UPDATE `mail`.`auth` SET `passwd`=? ".
                    " WHERE `login`=(SELECT SUBSTRING_INDEX(`username`, '@', 1)".
                    " FROM `forgot_password` JOIN `users`".
                    " ON (`forgot_password`.`user_id`=`users`.`user_id`)".
                    " WHERE token=?)",
                    array($new_password, $token));
                
                if($this->rc->db->affected_rows()==1)
                {
                    $this->rc->db->query("UPDATE forgot_password set token=null, token_expiration=null WHERE token=?",$token);
                    $message = $this->gettext('password_changed','forgot_password');
                    $type = 'confirmation';
                    $this->rc->output->command('display_message', $message, $type);
                    $this->rc->output->send('login');
                } else
                {
                    $message = $this->gettext('password_not_changed','forgot_password');
                    $type = 'error';
                    $this->rc->output->command('display_message', $message, $type);
                    $this->rc->output->send('login');
                }
            }
            /*      $this->rc->output->command('display_message', $message, $type);
            $this->rc->output->send('login');
            $this->rc->output->send('forgot_password.new_password_form');*/
        } else
        {
            $message = $this->gettext('password_confirmation_invalid','forgot_password');
            $this->rc->output->command('display_message', $message, 'error');
            $this->rc->output->send('forgot_password.new_password_form');
        }
    }

    function new_password_form($a)
    {
        if($a['action'] != 'plugin.new_password_form' || !isset($_SESSION['temp']))
            return $a;
        $rcmail = rcmail::get_instance();
        // JRE - You will need to adjust table name to whatever table name you use for your users in roundcubedb
        $sql_result = $this->rc->db->query(
            "SELECT * FROM ".$this->rc->db->table_name('users', true)." u " .
            " INNER JOIN forgot_password fp ON u.user_id = fp.user_id " .
            " WHERE fp.token=? and token_expiration >= now()",
            rcube_utils::get_input_value('_t',rcube_utils::INPUT_GET));
        
        $userrec = $this->rc->db->fetch_assoc($sql_result);
        if($userrec)
        {
            $this->rc->output->send("forgot_password.new_password_form");
        } else
        {
            $message = $this->gettext('invalidtoken','forgot_password');
            $type = 'error';
            $this->rc->output->command('display_message', $message, 'error');
            $this->rc->kill_session();
            $this->rc->output->send('login');
        }
    }
    
    function forgot_password_reset($a)
    {
        if($a['action'] != "plugin.forgot_password_reset" || !isset($_SESSION['temp']))
            return $a;
                
        // kill remember_me cookies
        setcookie ('rememberme_user','',time()-3600);
        setcookie ('rememberme_pass','',time()-3600);
        
        $rcmail = rcmail::get_instance();
        
        //user must be user@domain
        //samoilov 28.04.2019 fix of domain in login and existence of user check
        $user = trim(urldecode($_GET['_username']));
        
        if (strpos($user,'@')===false)
        {
            $user=$user.'@ksc.ru';
        }
        if ($user)
        {
            $sql_result = $this->rc->db->query("SELECT user_id FROM ".$this->rc->db->table_name('users', true)."WHERE  username=?", $user);
            $userrec = $this->rc->db->fetch_assoc($sql_result);
            if ($userrec['user_id']!='')
            {
                //    echo '<script>console.log("'.$userrec['user_id'].'")</script>';
                      // JRE - You will need to adjust table name to whatever table name you use for your users in roundcubedb
                $sql_result = $this->rc->db->query(
                    "SELECT u.user_id, fp.alternative_email, fp.token_expiration, fp.token_expiration < now() as token_expired " .
                    " FROM ".$this->rc->db->table_name('users', true)." u " .
                    " INNER JOIN forgot_password fp on u.user_id = fp.user_id " .
                    " WHERE  u.username=?", $user);
                $userrec = $this->rc->db->fetch_assoc($sql_result);
                
                if (is_array($userrec) && $userrec['alternative_email'])
                {
                    if($userrec['token_expiration'] && !$userrec['token_expired'])
                    {
                        $message = $this->gettext('checkaccount','forgot_password');
                        $type = 'confirmation';
                    } else
                    {
                        if ($this->send_email_with_token($userrec['user_id'], $userrec['alternative_email'], $user))
                        {
                            $message = $this->gettext('checkaccount','forgot_password');
                            $type = 'confirmation';
                        } else
                        {
                            $message = $this->gettext('sendingfailed','forgot_password');
                            $type = 'error';
                        }
                    }
                } else
                {
                    $this->send_alert_to_admin($user);
                    $message = $this->gettext('senttoadmin','forgot_password');
                    $type = 'notice';
                }
            } else
            {
                $message = $this->gettext('forgot_passwordusernotfound','forgot_password');
                $type = 'error';
            }
        } else
        {
            $message = $this->gettext('forgot_passworduserempty','forgot_password');
            $type = 'error';
        }
        $this->rc->output->command('display_message', $message, $type);
        $this->rc->kill_session();
        // samoilov 28.01.2020 commented out below to clear username from input field
        //$_POST['_user'] = $user;
        $this->rc->output->send('login');
    }
    
    function add_labels_to_login_page($a)
    {
        if($a['template'] != "login")
            return $a;
        
        $rcmail = rcmail::get_instance();
        $this->rc->output->add_label(
            'forgot_password.forgotpassword',
            'forgot_password.forgot_passworduserempty',
            'forgot_password.forgot_passwordusernotfound'
        );
        return $a;
    }
    
    function add_labels_to_mail_page($a)
    {
        $rcmail = rcmail::get_instance();
        $this->rc->output->add_label('forgot_password.no_alternative_email_warning');
        $this->rc->output->add_script('rcmail.message_time = 10000;');
        return $a;
    }
    
    function html($p)
    {
        $rcmail = rcmail::get_instance();
        $content = "<h1>" . taskbar . "</h1>";
        $this->rc->output->add_footer($content);
        return $p;
    }
    
    // samoilov 27.05.2020 function to get OP admins email for requesting user
    private function get_op_admin_emails($user)
    {
        $rcmail = rcmail::get_instance();
        //samoilov 27.05.2020 get OP for requesting user
        $sql_result = $this->rc->db->query(
            "SELECT `OP` FROM `mail`.`auth`".
            " WHERE concat(`login`,'@',`domain`) =?", $user);
        $OP_arr = $this->rc->db->fetch_assoc($sql_result);
        // samoilov 27.05.2020 OP is ISC or IEN or GI - under FIC protection =)
        if ($OP_arr['OP']=='ГИ'|| $OP_arr['OP']=='ЦГП' || $OP_arr['OP']=='ЦЭС')
        {
            $OP = 'ФИЦ';
        } else
        {
            $OP = $OP_arr['OP'];
        }

        //SELECT concat(`login`,'@',`domain`) FROM auth WHERE `isAdmin`='YES' AND OP='ГоИ';
        $sql_result = $this->rc->db->query(
            "SELECT concat(`login`,'@',`domain`) as email".
            " FROM `mail`.`auth`".
            " WHERE `isAdmin`='YES' AND `OP`=?", $OP);
            //echo '<script>console.log("'.print_r($sql_result).'")</script>';
            //while ($admins_arr = $this->rc->db->fetch_assoc($sql_result)) {
            //  echo '<script>console.log("'.print_r($admins_arr).'")</script>';
            //    }
        return $sql_result;
    }
    
    private function send_email_with_token($user_id, $alternative_email, $user)
    {
        $rcmail = rcmail::get_instance();
        $token = md5($alternative_email.microtime());
        $sql = "UPDATE forgot_password " .
            " SET token='$token', token_expiration=now() + INTERVAL " . TOKEN_EXPIRATION_TIME_MIN . " MINUTE" .
            " WHERE user_id=$user_id";
        $this->rc->db->query($sql);
        
        $file = dirname(__FILE__)."/localization/{$this->rc->user->language}/reset_pw_body.html";
        // The 'login' portion of the link is OPTIONAL and only required if that's the default login screen for your RC installation.
        $link = "http://{$_SERVER['SERVER_NAME']}/?_task=settings&_action=plugin.new_password_form&_t=$token";
        $body = strtr(file_get_contents($file), array('[LINK]' => $link));
        $subject = $this->rc->gettext('email_subject','forgot_password') . " ящика ".$user;
        //              echo '<script>console.log("'.$alternative_email.'")</script>';
        return $this->send_html_and_text_email(
            $alternative_email,
            //$this->get_from_email($alternative_email),
            //$this->get_from_email($this->rc->config->get('admin_email')),
            $this->get_from_email($this->rc->config->get('default_smtp_user')),
            $subject,
            $body);
    }
    
    private function send_alert_to_admin($user_requesting_new_password)
    {
        $rcmail = rcmail::get_instance();
        //samoilov 28.04.2019 fix of admin alert body
        //$file = dirname(__FILE__)."/localization/{$this->rc->user->language}/reset_pw_body.html";
        $file = dirname(__FILE__)."/localization/{$this->rc->user->language}/alert_for_admin_to_reset_pw.html";
        $body = strtr(file_get_contents($file), array('[USER]' => $user_requesting_new_password));
        $subject = $this->rc->gettext('admin_alert_email_subject','forgot_password');
        //echo '<script>console.log("'.$subject.'")</script>';
        // samoilov 27.05.2020 send to all OP admins user's request 
        $sql_result = $this->get_op_admin_emails($user_requesting_new_password);
        //samoilov 27.05.2020 make a string of to addresses with comma
        while ($admins = $this->rc->db->fetch_assoc($sql_result))
        {
            $to_admins .= $admins['email'] . ',';
        }
        echo '<script>console.log("'.$to_admins.'")</script>';
        return $this->send_html_and_text_email(
            //$this->rc->config->get('admin_email'),
            //$admins['email'],
            $to_admins,
            $this->get_from_email($user_requesting_new_password),
            $subject,
            $body);
            //echo '<script>console.log("'.$admins['email'].'")</script>';
    }

    private function get_from_email($email)
    {
        $parts = explode('@',$email);
        //samoilov 29.04.2019 fix of 'from:' field
        //return 'no-reply@'.$parts[1];
        return $parts[0].'@ksc.ru';
    }
    
    private function send_html_and_text_email($to, $from, $subject, $body)
    {
        $rcmail = rcmail::get_instance();

        $ctb = md5(rand() . microtime());
        $headers  = "Return-Path: $from\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: multipart/alternative; boundary=\"=_$ctb\"\r\n";
        $headers .= "Date: " . date('r', time()) . "\r\n";
        $headers .= "From: Почтовая система КНЦ РАН <$from>\r\n";
        $headers .= "To: $to\r\n";
        $headers .= "Subject: $subject\r\n";
        $headers .= "Reply-To: $from\r\n";

        $msg_body .= "Content-Type: multipart/alternative; boundary=\"=_$ctb\"\r\n\r\n";

        $txt_body  = "--=_$ctb";
        $txt_body .= "\r\n";
        $txt_body .= "Content-Transfer-Encoding: 7bit\r\n";
        $txt_body .= "Content-Type: text/plain; charset=" . 'RCMAIL_CHARSET' . "\r\n";
        $LINE_LENGTH = $this->rc->config->get('line_length', 75);
        $h2t = new rcube_html2text($body, false, true, 0);
        $txt = rcube_mime::wordwrap($h2t->get_text(), $LINE_LENGTH, "\r\n");
        $txt = wordwrap($txt, 998, "\r\n", true);
        $txt_body .= "$txt\r\n";
        $txt_body .= "--=_$ctb";
        $txt_body .= "\r\n";
        
        $msg_body .= $txt_body;
        $msg_body .= "Content-Transfer-Encoding: quoted-printable\r\n";
        $msg_body .= "Content-Type: text/html; charset=" . 'RCMAIL_CHARSET' . "\r\n\r\n";
        $msg_body .= str_replace("=","=3D",$body);
        $msg_body .= "\r\n\r\n";
        $msg_body .= "--=_$ctb--";
        $msg_body .= "\r\n\r\n";
        
        // send message
        if (!is_object($this->rc->smtp))
        {
            $this->rc->smtp_init(true);
        }
        
        if ($this->rc->config->get('smtp_pass') == "%p")
        {
            $this->rc->config->set('smtp_server', $this->rc->config->get('default_smtp_server'));
            $this->rc->config->set('smtp_user', $this->rc->config->get('default_smtp_user'));
            $this->rc->config->set('smtp_pass', $this->rc->config->get('default_smtp_pass'));
        }
        
        $this->rc->smtp->connect();
        if ($this->rc->smtp->send_mail($from, $to, $headers, $msg_body))
        {
            return true;
        } else
        {
            rcube::write_log('errors','response:' . print_r($this->rc->smtp->get_response(),true));
            rcube::write_log('errors','errors:' . print_r($this->rc->smtp->get_error(),true));
            return false;
        }
    }
}
?>
