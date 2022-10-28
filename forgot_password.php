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
 * - major re-write
 * - added recovery email verification
 * - re-use login page for entering recovery password
 * - use password plugin for password update
 * @url https://github.com/bradley-jarvis/roundcube-forgot_password
 */
class forgot_password extends rcube_plugin 
{
    public $task = 'login|logout|settings|mail';
    
    private $rc;
    private $tag = array('new'=>'','old'=>'');
    
    function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();
	
	$this->rc->db->query('CREATE TABLE'.
		' IF NOT EXISTS '.$this->rc->db->table_name('forgot_password',true).' (' .
		' user_id int(11) NOT NULL,' .
		' email varchar(200) NOT NULL,' .
		' recover varchar(256) DEFAULT NULL,' .
		' expiration datetime DEFAULT NULL,' .
		' validate varchar(256) DEFAULT NULL,' .
		' PRIMARY KEY (`user_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8');

        $this->add_texts('localization/');

	$this->load_config('config.inc.php');

	$this->tag['old']=isset($_SESSION['forgot_password.tag'])?$_SESSION['forgot_password.tag']:'';
	$_SESSION['forgot_password.tag']=base64_encode(random_bytes(12));
	$this->tag['new']=$_SESSION['forgot_password.tag'];

	if ($this->rc->task == 'login' || $this->rc->task == 'logout')
	{
            	$this->add_hook('render_page', array($this, 'login_form'));
        	$this->add_hook('startup',array($this, 'recover'));

        	$query=$this->_recover(rcube_utils::get_input_value('_token',rcube_utils::INPUT_GP));
		if ($this->rc->action != 'forgot_password.update' || $query==null)
	                $this->include_script('js/forgot_password.js');
	} else
        {
		$this->add_hook('logout', array($this, 'logout'));

		if ($this->rc->task == 'mail')
		{
           		$this->add_hook('messages_list', array($this, 'show_warning_recovery_email'));
		}
            	else if ($this->rc->task == 'settings')
            	{
                	if ($this->rc->action == 'plugin.password')
                    		$this->add_hook('render_page', array($this, 'update_form'));
            	}
        }
        $this->add_hook('startup',array($this, 'validate'));
	$this->register_action('plugin.password-save-forgot_password', array($this, 'password_save'));
    }

    function logout()
    {
	    unset($_SESSION['show_warning_recovery_email']);
	unset($_SESSION['forgot_password.tag']);
    }

    function update_form()
    {
	if (!isset($this->rc->user->ID)) return;

        $query = $this->rc->db->query(
		'SELECT email FROM '.$this->rc->db->table_name('forgot_password',true) .
		' WHERE user_id = '.$this->rc->user->ID, PDO::FETCH_ASSOC);
				$query = is_bool($query)?null:$query->fetch();
        $this->rc->output->add_script(
            '$(document).ready(function($){' .
            '$("#password-form table :first").prepend(\'' .
            '<tr class="form-group row">' .
            '<td class="title col-sm-4"><label class="col-form-label" for="recovery_email">' .
            $this->gettext('recovery_email','forgot_password') .
            ':</label></td>' .
            '<td class="col-sm-8"><input class="form-control" type="text" autocomplete="off" id="recovery_email" ' .
                'name="_recovery_email" value="' . (is_array($query)?$query['email']:'') . '"></td>' .
            '</tr>\');' .
            '$("#password-form").attr("action",$("#password-form").attr("action").replace(".password-save",".password-save-forgot_password"));' .
	    '$("button[value=\"Save\"]").attr("onclick",$("button[value=\"Save\"]").attr("onclick").replace(".password-save",".password-save-forgot_password"));' .
	    'rcmail.register_command(\'plugin.password-save-forgot_password\', function() {rcmail.gui_objects.passform.submit();},true);' .
            '});');
        
        //disable password plugin's javascript validation
        $this->include_script('js/change_save_button.js');
    }
    
    function login_form($args)
    {
	if ($args['template'] != "login" && $args['template'] != 'logout') return $args;

	$this->rc->gettext(array(
		'name'=>'forgot_password.href',
		'en_us'=>'/?_task=login&_action=forgot_password.recover&_tag='.urlencode($this->tag['new']).'&_username='));

	    $this->rc->output->add_label(
		    'forgot_password.label',
		    'forgot_password.href',
            'forgot_password.userempty'
	);
        return $args;
    }
    
    function password_save()
    {
	// update password/recovery email from password web form
        $query = $this->rc->db->query(
		'SELECT username FROM '.$this->rc->db->table_name('users',true).
		' WHERE user_id = '.$this->rc->user->ID,
		PDO::FETCH_ASSOC)->fetch();
	$user = $query ? $query['username'] : '';

        $query = $this->rc->db->query(
		'SELECT email FROM '.$this->rc->db->table_name('forgot_password',true).
		' WHERE user_id = '.$this->rc->user->ID,
		PDO::FETCH_ASSOC)->fetch();
	$recovery = $query ? $query['email'] : '';
	
	$email = rcube_utils::get_input_value('_recovery_email',rcube_utils::INPUT_POST);
        
	if (strcmp($email,$user)==0)
	{
            // don't allow an recovery email address that matches this account
            $this->rc->output->command('display_message', 
                strtr($this->gettext('email_match','forgot_password'),
                array('[EMAIL]'=>$email, '[USER]'=>$user, '[ID]'=>$this->rc->user->ID)),
                'error');
	} else if (strcmp($email,$recovery)!=0)
	{
            // check that the recovery email is valid
	    if (preg_match('/.+@[^.]+\..+/Umi',$email))
	    {
		    // yep! so send a validation email
		    $this->validate();
            } else
            {
		$this->rc->output->command('display_message', 
			strtr($this->gettext('email_invalid','forgot_password'),
			array('[EMAIL]'=>$email, '[EMAIL_OLD]'=>$recovery, '[USER]'=>$user)),
			'error');
	    }
	}

	/// add the forgot password js update
        $this->update_form();

	// only do password update if new or confirmation passwords are set
	if (rcube_utils::get_input_value('_newpasswd',rcube_utils::INPUT_POST)!='' ||
	    rcube_utils::get_input_value('_confpasswd',rcube_utils::INPUT_POST)!='')
        {
	    $this->rc->plugins->get_plugin('password')->password_save();
        } else
	{
            // redraw the password form
            $this->register_handler('plugin.body',
                array($this->rc->plugins->get_plugin('password'), 'password_form'));
            $this->rc->overwrite_action('plugin.password');
            $this->rc->output->send('plugin');
        }
    }

    function show_warning_recovery_email()
    {
        if (isset($_SESSION['show_warning_recovery_email'])) return;
        
	$_SESSION['show_warning_recovery_email'] = true;
        $query = $this->rc->db->query(
		'SELECT u.username user, fp.email email, fp.validate validate' .
		' FROM '.$this->rc->db->table_name('users',true).' u' .
		' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp' .
		' ON u.user_id = fp.user_id' .
		' WHERE u.user_id = '.$this->rc->user->ID, PDO::FETCH_ASSOC)->fetch();
  
	if (!is_array($query) || strlen($query['email'])<0)
	    // display set ercover email notice
            $this->rc->output->command('display_message',
            	strtr($this->gettext('recovery_email_warning','forgot_password'),
			array("[LINK]"=>'_task=settings&_action=plugin.password')),
		'notice');
	else if (strlen($query['validate']))
	    // display validate recover email notice with option to resed validation
            $this->rc->output->command('display_message',
            	strtr($this->gettext('validate_email_warning','forgot_password'),
			array("[LINK]"=>'_task='.$this->rc->task.'&_action=forgot_password.validate_send&_username='.urlencode($query['user']))),
		'notice');

	// remove recover token from forgot_password table on successful login
        $this->rc->db->query(
		'UPDATE '.$this->rc->db->table_name('forgot_password',true).
		' SET recover=NULL'.
		' WHERE user_id = '.$this->rc->user->ID
	);
    }

    function _recover($token)
    {
	    $query=$this->rc->db->query(
	    'SELECT u.user_id id, u.username user, u.mail_host host, fp.email email'.
	    ' FROM '.$this->rc->db->table_name('users',true).' u'.
	    ' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp'.
	    ' ON u.user_id = fp.user_id' .
	    ' WHERE fp.recover = \''.$this->rc->db->escape($token).'\' and fp.expiration >= now()',
	    PDO::FETCH_ASSOC);
	    return $query?$query->fetch():null;
    }

    function recover($args)
    {
	    $vars=array(
		'[USER]' => rcube_utils::get_input_value('_username',rcube_utils::INPUT_GET),
		'[ACTION]' => $args['action'],
		'[TOKEN]' => rcube_utils::get_input_value('_token',rcube_utils::INPUT_GP),
		'[TAG]' => rcube_utils::get_input_value('_tag',rcube_utils::INPUT_GP),
		'[PASSWORD]' => rcube_utils::get_input_value('_pass',rcube_utils::INPUT_GP),
		'[STAG]' => $this->tag['old']
	    );

	if ($vars['[ACTION]'] == "forgot_password.recover")
        {
        if ($vars['[USER]'])
        {
		    if (strcmp($vars['[STAG]'], $vars['[TAG]']))
		    {
			    $message = strtr('Invalid tag for email recovery {ID:[TAG]-[STAG]}',$vars);
				    ;//$this->gettext('sendingfailed','forgot_password');
			    $type = 'error';
		    } else
		    {

			    $vars['[EMAIL]']=strtr($this->rc->config->get('smtp_user'),
				    array(
					    '%u'=>$vars['[USER]'],
					    '%n'=>$_SERVER["HTTP_HOST"],
				    '%t'=>explode('.',$_SERVER["HTTP_HOST"],2)[1]));
                $record = $this->rc->db->query(
                    'SELECT u.user_id id, fp.email email, fp.recover, fp.expiration < now() as expired' .
                    ' FROM '.$this->rc->db->table_name('users', true).' u '.
                    ' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp on u.user_id = fp.user_id ' .
		    ' WHERE  u.username = \''.$this->rc->db->escape($vars['[EMAIL]']).'\'',
		    PDO::FETCH_ASSOC);
		$record=$record?$record->fetch():null;
		$vars['[RECOVERY]']=is_array($record)?$record['email']:null;

		if ($vars['[RECOVERY]'] && ($rv=$this->_send_email($vars['[EMAIL]'], $vars['[RECOVERY]']))!=null)
                {
                            $message = strtr($this->gettext('sendingfailed','forgot_password'),$vars);
                            $type = 'error';
            } else
            {
		$message = strtr($this->gettext('checkaccount','forgot_password'),$vars);
		//$message = strtr('Send password recovery to [USER]:[EMAIL]',$vars);
                $type = 'confirmation';
	    }
		    }
        } else
        {
	    $message = strtr($this->gettext('userempty','forgot_password'),$vars);
            $type = 'error';
	}

	$this->rc->output->command('display_message', strtr($message, $vars), $type);
        //$this->rc->kill_session();
	$this->rc->output->send('login');
	} else if ($vars['[ACTION]'] == "forgot_password.update")
	{

	        $query=$this->_recover($vars['[TOKEN]']);

		if ($query)
		{
		$alphabet=join('',range('A','Z'));
		$vars['[ID]']=$query['id'];
		$vars['[USER]']=$query['user'];
		$vars['[EMAIL]']=$query['email'];
		$vars['[HOST]']=$query['host'];

		unset($message);
		$type = null;
		
		// check if new password has been submitted and tags match
		if (!strcmp(strtr($vars['[TAG]'],$alphabet.strtolower($alphabet),strtolower($alphabet).$alphabet),$vars['[STAG]']) && 
			strlen($vars['[PASSWORD]'])>0)
		{
			// pass new password onto password plugin for validation/update
			$plugin = $this->rc->plugins->get_plugin('password');
			if (strlen($vasr['[USER]'])<=0)
			{
				$message = 'Cannot find recovery user';
			} if ($plugin)
			{
				// attempt to update password
				$message = $plugin->save(null, $vars['[PASSWORD]'], $vars['[USER]'], $vars['[HOST]']);
			} else
			{
				$message = 'Unable to recover password because password plugin is not installed';
			}
			if (!$message)
			{
				$message = 'Successfully recovered password';
				$type = 'confirmation';
				$query = null;
			}
		} else
		{
			$message = 'Enter new password ([PASSWORD],[TAG],[STAG])';
			$type = 'notice';
		}
        
		// update login page to recover password
		if ($query)
		{
			$tag = strtr($this->tag['new'],$alphabet.strtolower($alphabet),strtolower($alphabet).$alphabet);
	        $this->rc->output->add_script(
			'$(document).ready(function($){' .
				'var clone=$("#login-form").find("input").first();' .
				'clone.attr("name","_tag");' .
				'clone.attr("value","'.$tag.'");' .
				'clone.prependTo("#login-form");' .
				'clone=clone.clone();' .
				'clone.attr("name","_token");' .
				'clone.attr("value","'.$vars['[TOKEN]'].'");' .
				'clone.prependTo("#login-form");' .
				'$("head > title").html("Roundcube Webmail :: Recover Password");' .
				'$("#login-form").find("tr").first().remove();' .
				'$("#login-form [name=\"_action\"").val("forgot_password.update");' .
				'$("#rcmloginsubmit").html("Recover Password");' .
				'$("#rcmloginsubmit").attr("id","rcmrecoverpassword");' .
				'})');
		}

		if ($message)
		$this->rc->output->command('display_message', strtr($message, $vars), $type?$type:'error');
        } else
        {
            $this->rc->output->command('display_message',strtr($this->gettext('invalidtoken','forgot_password'),$vars),'error');
            $this->rc->kill_session();
	}
	$this->rc->output->send('login');
	}
	return $args;
    }
    
		function validate($args=null)
    {
	$vars=array(
		'[USER]' => rcube_utils::get_input_value('_username',rcube_utils::INPUT_GP),
		'[EMAIL]' => rcube_utils::get_input_value('_recovery_email',rcube_utils::INPUT_GP),
		'[ID]' => $this->rc->user->ID,
		'[ACTION]' => rcube_utils::get_input_value('_action',rcube_utils::INPUT_GP),
	);
	if ($vars['[ACTION]']=='forgot_password.validate_send' ||
		$vars['[ACTION]']=='plugin.password-save-forgot_password')
	{
		#$vars['[USER]']=explode('@',$this->rc->get_user_name())[0];
		$vars['[USER]']=$this->rc->get_user_name();
		#if (strpos($vars['[USER]'],'@')<0)
	#	{
	#		   $vars['[USER]']=strtr($this->rc->config->get('smtp_user'),
	#			    array(
	#				    '%u'=>$vars['[USER]'],
	#				    '%n'=>$_SERVER["HTTP_HOST"],
	#			    '%t'=>explode('.',$_SERVER["HTTP_HOST"],2)[1]));
	#	}
                $record = $this->rc->db->query(
                    'SELECT fp.email email' .
                    ' FROM '.$this->rc->db->table_name('users', true).' u '.
                    ' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp on u.user_id = fp.user_id ' .
		    ' WHERE  u.username = \''.$this->rc->db->escape($vars['[USER]']).'\'',
				PDO::FETCH_ASSOC);

			$vars['[EMAIL_OLD]']=is_bool($record)?null:$record->fetch()['email'];

		#if (is_array($record))
		#{
		#$record=$record?$record->fetch():null;
		#} else
		#{
		#	$record['user']=$vars['[USER]'];
		#	$record['email']=rcube_utils::get_input_value('_recovery_email',rcube_utils::INPUT_GP),
		#}
	    	#if ($record && strlen($record['user'])>0)
				{
		    	#$vars['[USER]'] = $record['user'];
		    	#$vars['[EMAIL]'] = $record['email'];

	    		$rv = $this->_send_email($vars['[USER]'], $vars['[EMAIL]'], random_bytes(128));
					
					$type = 'confirmation';
					
					if ($rv != null)
					{
									$vars['[ERROR]'] = $rv['error'];
									$vars['[RESPONSE]'] = $rv['response'];
									
									$type = 'error';
									$message = 'There was a problem sending verify email, [RESPONSE] - [ERROR]';
					} else
											#$this->gettext('email_update','forgot_password'), 
									$message = 'update email recovery for [USER] from [EMAIL_OLD] to [EMAIL]'; 
			$this->rc->output->command('display_message',strtr($message, $vars), $type);
	 	}# else
	   # 	{
		#	$this->rc->output->command('display_message', 
	#			strtr('Problem getting validation data for user {[ACTION]} ([ID]) - "[SQL]"', $vars),
		#		'error');
	  #  	}
	} else if ($vars['[ACTION]']=='forgot_password.validate_check')
	{
		$action = rcube_utils::get_input_value('_action',rcube_utils::INPUT_GET);
		$token = rcube_utils::get_input_value('_token',rcube_utils::INPUT_GET);

	$query = $this->rc->db->query('SELECT u.user_id id, u.username user, fp.email email'.
		' FROM '.$this->rc->db->table_name('users',true).' u'.
		' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp'.
		' ON u.user_id = fp.user_id'.
		' WHERE fp.validate=\''.$this->rc->db->escape($token).'\'',
		PDO::FETCH_ASSOC)->fetch();
	
	$query = $query ? $query : array('user'=>'', 'email'=>'');
	$vars = array(
		'[ACTION]'=>$action,
		'[TOKEN]'=>$token,
		'[EMAIL]'=>$query['email'],
		'[ID]'=>$query['id'],
		'[USER]'=>$query['user']);

	if ($query['email'])
	{
		$this->rc->db->query('UPDATE '.$this->rc->db->table_name('forgot_password',true).
			' SET validate=NULL'.
			' WHERE user_id = '.$vars['[ID]']);
		$this->rc->output->command('display_message', 
			//strtr($this->gettext('email_invalid','forgot_password'),
			strtr("Recovery email [EMAIL] validated for [USER]", $vars), 'confirmation');
	} else
	{
		$this->rc->output->command('display_message', 
			//strtr($this->gettext('email_invalid','forgot_password'),
						strtr("Invalid recovery token", $vars), 'error');
	}
	}
	return $args;
    }
    
    private function _send_email($user, $to = '', $token = '')
    {
	$admin = '';
	$subject = '';
	$link = '';
	
        if ($to == '')
	{
	    // no alternative email address
	    return false;
	    $subject = 'admin';
	} if ($token != '')
	    {
		$subject = 'validate';
		$token = base64_encode($token);
                $link = "_action=forgot_password.validate_check&_token=".urlencode($token);
		
                $this->rc->db->query(
			'INSERT INTO '.$this->rc->db->table_name('forgot_password',true).' (user_id, email, recover, validate)'.
			' SELECT u.user_id,\''.$this->rc->db->escape($to).'\',\'\',\''.$this->rc->db->escape($token).'\''.
			' FROM '.$this->rc->db->table_name('users',true).' u'.
			' LEFT JOIN '.$this->rc->db->table_name('forgot_password',true).' fp'.
			' ON u.user_id = fp.user_id'.
			' WHERE u.username = \''.$this->rc->db->escape($user).'\''.
			' ON DUPLICATE KEY UPDATE'.
			' email = \''.$this->rc->db->escape($to).'\','.
			' recover = \'\','.
			' validate = \''.$this->rc->db->escape($token).'\''
		);
	    } else
	    {
		$subject = 'recover';
		$token = base64_encode(random_bytes(128));
		$link = "_task=login&_action=forgot_password.update&_token=".urlencode($token);
		$this->rc->db->query(
			'INSERT INTO '.$this->rc->db->table_name('forgot_password',true).' (user_id, email, recover, expiration)'.
			' SELECT fp.user_id, \''.$this->rc->db->escape($to).'\', \''.$this->rc->db->escape($token).'\','.
			' now() + INTERVAL '.$this->rc->config->get('default_token_expire').' MINUTE'.
			' FROM '.$this->rc->db->table_name('users',true).' u'.
			' INNER JOIN '.$this->rc->db->table_name('forgot_password',true).' fp'.
			' ON u.user_id = fp.user_id'.
			' WHERE u.username = \''.$this->rc->db->escape($user).'\''.
			' ON DUPLICATE KEY UPDATE'.
			' email = \''.$this->rc->db->escape($to).'\','.
			' recover = \''.$this->rc->db->escape($token).'\','.
			' expiration = now() + INTERVAL '.$this->rc->config->get('default_token_expire').' MINUTE');
	}

	$vars = array(
        	'[LINK]' => "http://{$_SERVER['SERVER_NAME']}/?$link",
		'[USER]' => $user,
		'[DATE]' => date('r',time()),
		'[FROM]' => $this->rc->config->get('admin_email'),
		'[TO]' => $to,
		'[BOUNDARY]' => '_'.md5(rand() . microtime()));
	$vars['[SUBJECT]'] = strtr($this->rc->gettext('subject_'.$subject,'forgot_password'),$vars);
	$vars['[BODY]'] = str_replace('=','=3D',strtr($this->rc->gettext('email_'.$subject,'forgot_password'), $vars));
	$vars['[HTML]'] = rcube_mime::wordwrap(
			(new rcube_html2text($vars['[BODY]'], false, true, 0))->get_text(),
			$this->rc->config->get('line_length', 75),
			"\r\n").

	
        $headers  = strtr("Return-Path: [FROM]\r\n".
            	"MIME-Version: 1.0\r\n".
        	"Content-Type: multipart/alternative; boundary=\"[BOUNDARY]\"\r\n".
        	"Date: [DATE]\r\n".
        	"From: [FROM]\r\n".
        	"To: [TO]\r\n".
        	"Subject: [SUBJECT]\r\n".
        	"Reply-To: [FROM]\r\n", $vars);

        $msg_body = strtr("Content-Type: multipart/alternative; boundary=\"[BOUNDARY]\"\r\n\r\n".
		"--[BOUNDARY]\r\n".
        	"Content-Transfer-Encoding: 7bit\r\n".
        	"Content-Type: text/plain; charset=RCMAIL_CHARSET\r\n".
		"[HTML]\r\n".
        	"--[BOUNDARY]\r\n".
        	"Content-Transfer-Encoding: quoted-printable\r\n".
        	"Content-Type: text/html; charset=RCMAIL_CHARSET\r\n\r\n".
		"[BODY]\r\n\r\n".
		"--[BOUNDARY]--\r\n\r\n", $vars);
        
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
        if ($this->rc->smtp->send_mail($vars['[FROM]'], $vars['[TO]'], $headers, $msg_body))
        {
            return null;
        } else
        {
            rcube::write_log('errors','response:' . print_r($this->rc->smtp->get_response(),true));
            rcube::write_log('errors','errors:' . print_r($this->rc->smtp->get_error(),true));
	    return [
		    'response'=>implode(',',$this->rc->smtp->get_response()),
		'error'=>implode(',',$this->rc->smtp->get_error())
	    ];
        }
    }
}
?>
