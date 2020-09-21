$(function() {
  $("#password_visibility").click(function(){
        var pass_input = document.getElementById("id_password1");
        if (pass_input.type === "password") {
            pass_input.type = "text";
            $(this).removeClass("fa-eye").addClass("fa-eye-slash")
        } else {
            pass_input.type = "password";
            $(this).removeClass("fa-eye-slash").addClass("fa-eye")
        }
   });
});

$(function() {
  $("#password_visibility1").click(function(){
        var pass_input = document.getElementById("id_password2");
        if (pass_input.type === "password") {
            pass_input.type = "text";
            $(this).removeClass("fa-eye").addClass("fa-eye-slash")
        } else {
            pass_input.type = "password";
            $(this).removeClass("fa-eye-slash").addClass("fa-eye")
        }
   });
});
function submit_form() {
    $('#id_username').val($('#id_email').val())
    $('form[name="signup-form"]').submit()
}





$(document).ready(function(){

$(function(){
 
    $(document).on( 'scroll', function(){
 
        if ($(window).scrollTop() > 100) {
            $('.scroll-top-wrapper').addClass('show');
        } else {
            $('.scroll-top-wrapper').removeClass('show');
        }
    });
 
    $('.scroll-top-wrapper').on('click', scrollToTop);
});
 
function scrollToTop() {
    verticalOffset = typeof(verticalOffset) != 'undefined' ? verticalOffset : 0;
    element = $('body');
    offset = element.offset();
    offsetTop = offset.top;
    $('html, body').animate({scrollTop: offsetTop}, 500, 'linear');
}

});



