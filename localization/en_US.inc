<?php

$labels = array();
$labels['label'] = 'I forgot my password';
$labels['passwordrecovery'] = 'Forgot Password';
$labels['pwreminder'] = 'Password Reminder';
$labels['forgot_passwordform'] = 'Password reset form';
$labels['forgot_passwordenabled'] = 'Reminder enabled';
$labels['forgot_passwordisenabled'] = 'Reminder is enabled';
$labels['forgot_passworddisabled'] = 'Reminder is disabled';
$labels['forgot_passwordaddress'] = 'Send Password to';
$labels['forgot_passwordquestion'] = 'Secret Question';
$labels['forgot_passwordanswer'] = 'Secret Answer';
$labels['forgot_passwordanswerconfirm'] = 'Confirm Secret Answer';
$labels['forgot_passwordaddidentity'] = 'Please add an identity';
$labels['forgot_passwordadd'] = 'add';
$labels['forgot_passwordresetpw'] = 'Submit';
$labels['forgot_passwordexit'] = 'Cancel';
$labels['new_password'] = 'New password';
$labels['new_password_confirmation'] = 'Confirmation';
$labels['no_alternative_email_warning'] = 'Enter an alternate email address.';
$labels['click_here'] = 'Click here';
$labels['recovery_email'] = 'Recovery Email';
$labels['save'] = 'Save';

$messages = array();
$messages['forgot_passwordquestionempty'] = 'Please enter your Secret Question';
$messages['userempty'] = 'Please enter your user name';
$messages['forgot_passwordanswerempty'] = 'Please enter your Secret Answer';
$messages['forgot_passwordanswernotmatch'] = 'Secret Answer does not match';
$messages['forgot_passwordactive'] = 'Password Reminder will be enabled';
$messages['forgot_passwordinactive'] = 'Password Reminder is disabled';
$messages['usernotfound'] ='[USER] not found';
$messages['forgot_passwordimcomplete'] ='Your Reminder Settings are incomplete. Please contact the Administrator';
$messages['forgot_passwordfailed'] = 'Secret Answer is incorrect.';
$messages['sendingfailed'] = 'There was an error sending the email with instructions to generate a new password. Please try again later.';
$messages['checkaccount'] = 'Instructions to generate a new password has been sent to your recovery services if it exists {ID:[TAG]}';
$messages['senttoadmin'] = 'Your account does not have a recovery email address registered, an email has been sent to the Administrator to change your password.';
$messages['autobanned'] = 'Access is temporarily locked (too many invalid login attempts). Please try again later.';
$messages['nodeleteforgot_passwordaddress'] = 'This identity is linked to your Password reminder.';
$messages['invalidtoken'] = 'Invalid token.';
$messages['password_confirmation_invalid'] = 'Invalid password verification';
$messages['password_changed'] = 'Password changed successfully!';
$messages['password_not_changed'] = 'There was an error changing your password. Please try again later';
$messages['recovery_email_warning'] = 'You do not have an alternate email address, <a href="/?[LINK]">Add one now</a>!';
$messages['validate_email_warning'] = 'You have not validated your recovery address, <a href="/?[LINK]">Resend validation token</a>!';
$messages['email_update'] = 'Your backup email has been changed from "[EMAIL_OLD]".';
$messages['email_invalid'] = '"[EMAIL]" is not a valid email addres, please provide a valid alterate email address.';

$labels['subject_recover'] = 'Recover email account';
$messages['email_recover'] = 'To generate a new password for [USER], go to <a href="[LINK]">this link</a>';

$labels['subject_validate'] = 'Validate recovery email account';
$messages['email_validate'] = '<a href="[LINK]">Click the link</a> to validate recovery address for [USER]';

$labels['subject_admin'] = 'Request from [USER] for password change';
$messages['email_admin'] = '<p>User [USER] requested a password change but they do not have a recovery email address registered.</p><p>Please change the password and/or register a recovery email for this user.</p>';

$messages['email_match'] = 'Please choose a dfferent email address for recovery [USER]([ID])/[EMAIL]';

?>

