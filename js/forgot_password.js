function forgot_password()
{
  if ($('#rcmloginuser').val())
  {
    //$.post("./?_task=settings&_action=plugin.forgot_password_reset&_username=" +
    //  escape($('#rcmloginuser').val()),function(data){});
    document.location.href = rcmail.gettext('href','forgot_password') + encodeURIComponent($('#rcmloginuser').val());
      //"./?_task=login" +
      //"&_action=plugin.recover_password" +
      //"&_username=" + encodeURIComponent($('#rcmloginuser').val()) + 
      //"&_tag=" + encodeURIComponent(btoa(Math.floor(Math.random()*1000000000).toString()));
  }
  else
  {
    rcmail.display_message(
      rcmail.gettext('userempty','forgot_password'),
      'error'
    );
  }
}

$(document).ready(
  function($)
  {
    $('#login-form').append(
      '<a class="home" id="forgot_password" href="javascript:forgot_password();">' + rcmail.gettext('label','forgot_password') + '</a>'
    );
  }
);
