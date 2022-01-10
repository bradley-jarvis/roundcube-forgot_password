if (window.rcmail)
{
  rcmail.addEventListener(
    'init',
    function(evt)
    {
      rcmail.register_command(
        'plugin.password-save-without-validation', 
        function()
        {
          rcmail.gui_objects.passform.submit();
        },
        true);
    });
}

$(document).ready(
  function($)
  {
    //$('.button.mainaction').remove();
    //samoilov 28.04.2019 changed button type and appearance
    //	$('tr.form-group.row.alternative_email').append('<p><input type="button" value="Сохранить email" id="save_button" class="button mainaction"></p>')
    //	$('.alternative_email').append('<p><button class="button mainaction submit btn btn-primary" type="button" id="save_button" value="Сохранить email">Сохранить email</button></p>')
    //$('.box').after('<p><button class="button mainaction submit btn btn-primary" type="submit" id="save_button" value="Сохранить">Сохранить</button></p>')
    $('#password-form').attr('action').replace('plugin.password-save','plugin.password-save-without-validation');
});
