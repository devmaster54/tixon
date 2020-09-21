from django.conf.urls import url
from django.contrib.auth import views as auth_views

from apps.authentication.views import * 




urlpatterns = [
    url(r'^signup/', RegistrationView.as_view(), name='signup'),
    url(r'^get-started/', GetStartedView.as_view(), name='get_started'),
    url(r'^login/$', CustomLoginView.as_view(), name='login'),
    url(r'^logout/$', auth_views.LogoutView.as_view(next_page= '/'), name='logout'),\
    url(r'email-confirmation/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', ConfirmSignUpView.as_view(), name="email_confirmation"),
    url(r'^password_reset/$', CustomPasswordResetView.as_view(
        template_name='authentication/password_reset_confirm.html', 
        html_email_template_name='authentication/password_reset_email.html',
        subject_template_name='authentication/password_reset_subject.txt',), name='password_reset'),
    url(r'^password_reset/done/$', auth_views.PasswordResetDoneView.as_view(template_name='authentication/password_rest_done.html'), name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        CustomPasswordResetConfirmView.as_view(template_name='authentication/password-reset.html'), name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.PasswordResetCompleteView.as_view(template_name='authentication/password-reset-done.html'), name='password_reset_complete'),
    url(r'^password_change/$', PasswordChangeView.as_view(template_name='authentication/password-change.html'), name='password_change'),
    url(r'^password_change/done/$', auth_views.PasswordChangeDoneView.as_view(template_name='authentication/password-reset-done.html'), name='password_change_done'),
    
    url(r'^otp/$', TwoFactorAuthenticationView.as_view(), name='otp'),
    url(r'^check-otp/$', CheckTwoFactorAuthenticationView.as_view(), name='check_otp'),
    url(r'^send-otp/$', SendOTP.as_view(), name='send_otp'),

    url(r'^desable-otp/$', DesableMobileOtp.as_view(), name='desable_otp'),

    url(r'^kyc-upload/$', KYCUploadView.as_view(), name='kyc_upload'),
    url(r'^get-zip-regx/$', ZipRgxView.as_view(), name='get_zip_rgx'),
    url(r'^kyc-confirm/$', ConfirmKYCUpload.as_view(), name='kyc_confirm'),
    url(r'^kyc-detail/(?P<pk>\d+)/$', KYCDetailView.as_view(), name='kyc_detail'),
    url(r'^kyc-list/$', KYCProcessingListView.as_view(), name='kyc_list'),
    url(r'^active-list/$', KYCActiveListView.as_view(), name='active_list'),
    url(r'^rejected-list/$', KYCRejectedListView.as_view(), name='rejected_list'),
    url(r'^kyc-approve/(?P<pk>\d+)/$', KYCApproveView.as_view(), name='kyc_approve'),
    url(r'^kyc-reject/(?P<pk>\d+)/$', KYCRejectView.as_view(), name='kyc_reject'),
    url(r'^kyc-resubmission/(?P<pk>\d+)/$', KYCResubmitView.as_view(), name='kyc_resubmission'),

    url(r'^verify-2fa/$', VerifyGoogle2fa.as_view(), name='verify_2fa'),
    url(r'^enable-2fa/$', EmableGoogle2fa.as_view(), name='enable_2fa'),
    url(r'^ajax-enable-2fa/$', AjaxEmableGoogle2fa.as_view(), name='ajax_enable_2fa'),
    url(r'^desable-2fa/$', DesableGoogle2fa.as_view(), name='desable_2fa'),
    url(r'^enable-otp/$', Ajax2FAEnable.as_view(), name='enable_otp'),
    url(r'^validate-otp/$', AjaxOTPValidation.as_view(), name='validate_otp'),
    url(r'^ajax-disable-2fa/$', AjaxSend2FADisbleOTP.as_view(), name='disable_sms'),
    url(r'^upadte-phone-number/$', UpdateMobileNumber.as_view(), name='upadte_phone_number'),
    url(r'^ajax-upadte-phone-number/$', AjaxUpdateMobileNumber.as_view(), name='ajax_upadte_phone_number'),

    url(r'^add-bank-account/$', BankAccountView.as_view(), name='add_bank_account'),
    url(r'^add-wechat-account/$', WechatAccountView.as_view(), name='add_wechat_account'),
    url(r'^add-alipay-account/$', AlipayAccountView.as_view(), name='add_alipay_account'),
    url(r'^add-paypal-account/$', PaypalAccountView.as_view(), name='add_paypal_account'),
    url(r'^edit-bank-account/(?P<pk>\d+)/$', EditBankAccountView.as_view(), name='edit_bank_account'),
    url(r'^edit-paypal-account/(?P<pk>\d+)/$', EditPaypalAccountView.as_view(), name='edit_paypal_account'),
    url(r'^edit-wechat-account/(?P<pk>\d+)/$', EditWechatAccountView.as_view(), name='edit_wechat_account'),
    url(r'^edit-alipay-account/(?P<pk>\d+)/$', EditAlipayAccountView.as_view(), name='edit_alipay_account'),
    url(r'^remove-bank-account/$', RemoveBankAccountView.as_view(), name='remove_bank_account'),
    url(r'^remove-wechat-account/$', RemoveWechatAccountView.as_view(), name='remove_wechat_account'),
    url(r'^remove-alipay-account/$', RemoveAlipayAccountView.as_view(), name='remove_alipay_account'),
    # url(r'^edit-paypal-account/(?P<pk>\d+)/$', RemovePaypalAccountView.as_view(), name='remove_paypal_account'),
    # url(r'^edit-wechat-account/(?P<pk>\d+)/$', RemoveWechatAccountView.as_view(), name='remove_wechat_account'),
    # url(r'^edit-alipay-account/(?P<pk>\d+)/$', RemoveAlipayAccountView.as_view(), name='remove_alipay_account'),
    url(r'^contact-us/$', ContactUsView.as_view(), name='contact_us'),
]