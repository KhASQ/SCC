from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from home.models import UserProfile, Activity, Message
from home.forms import (
  EditUserForm,
  EditUserProfileForm,
  EditMessageForm,
)
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import authenticate, login, logout
import datetime
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core import signing
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.template import loader
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import generic
from django.views.decorators.debug import sensitive_post_parameters
from .forms import PasswordRecoveryForm, PasswordResetForm
from .signals import user_recovers_password


# function based views


def fire_alarm(request):

    return render(request, 'home/fire_alarm.html')


#log_in views


def login_en(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)

                return redirect('/home_mem_en/')

        else:
            return redirect('/accounts/login_en/')

    else:
        return render(request, 'home/login_en.html')


def login_ar(request):
    if request.method == 'POST':
      username = request.POST['username']
      password = request.POST['password']

      user = authenticate(request, username=username, password=password)
      if user is not None:
          if user.is_active:
              login(request, user)

              return redirect('/home_mem_ar/')

      else:
          return redirect('/accounts/login_ar/')

    else:
        return render(request, 'home/login_ar.html')


def logout_en(request):
    logout(request)

    return render(request, 'home/home_main_en.html')


def logout_ar(request):
    logout(request)

    return render(request, 'home/home_main_ar.html')


# home_main views


def home_main_en(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        sender_name = request.POST.get('name', '')
        sender_email = request.POST.get('email', '')
        content = request.POST.get('message', '')

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        email = EmailMessage('sender_name', 'content', to=['sadxsad91@gmail.com'])
        email.send()

        return redirect('/en/')

    else:
        form = EditMessageForm()

        return render(request, 'home/home_main_en.html', {'form': form})


def home_main_ar(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        sender_name = request.POST.get('name', '')
        sender_email = request.POST.get('email', '')
        content = request.POST.get('message', '')

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/')

    else:
        form = EditMessageForm()

        return render(request, 'home/home_main_ar.html', {'form': form})


# home_mem views


@login_required(login_url='/accounts/login_en/')
def home_mem_en(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)

        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/home_mem_en/')

    else:
        form = EditMessageForm()

        user = request.user

        user_profile = UserProfile.objects.get(user=user)

        args = {'form': form, 'user': user, 'user_profile': user_profile}

        return render(request, 'home/home_mem_en.html', args)


@login_required(login_url='/accounts/login_ar/')
def home_mem_ar(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)

        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/home_mem_ar/')

    else:
        form = EditMessageForm()

        user = request.user

        user_profile = UserProfile.objects.get(user=user)

        args = {'form': form, 'user': user, 'user_profile': user_profile}

        return render(request, 'home/home_mem_ar.html', args)


# members_points views


@login_required(login_url='/accounts/login_en/')
def members_points_en(request):

    users_profiles = UserProfile.objects.all()

    sum_points = 0
    sum_users = 0
    avr_points = 0

    for user_profile in users_profiles:
        sum_points = sum_points + user_profile.mem_points
        sum_users = sum_users + 1

    avr_points = sum_points / sum_users
    avr_75 = avr_points * 0.50

    sorted_profiles = UserProfile.objects.all().order_by('-mem_points')

    args = {'sorted_profiles': sorted_profiles, 'avr_points': avr_points, 'avr_75': avr_75}

    return render(request, 'home/members_points_en.html', args)


"""
@login_required(login_url='/accounts/login_ar/')
def members_points_ar(request):

    users_profiles = UserProfile.objects.all()

    args = {'users_profiles': users_profiles}

    return render(request, 'home/members_points_ar.html', args)
"""


# activity_pages views


def activity_main_en(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        sender_name = request.POST.get('name', '')
        sender_email = request.POST.get('email', '')
        content = request.POST.get('message', '')

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/activity_main_en/')

    else:
        form = EditMessageForm()

        activities = Activity.objects.all()

        args = {'form': form, 'activities': activities}

        return render(request, 'home/activity_main_en.html', args)


def activity_main_ar(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        sender_name = request.POST.get('name', '')
        sender_email = request.POST.get('email', '')
        content = request.POST.get('message', '')

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/activity_main_ar/')

    else:
        form = EditMessageForm()

        activities = Activity.objects.all()

        args = {'form': form, 'activities': activities}

        return render(request, 'home/activity_main_ar.html', args)


# activity_mem views


@login_required(login_url='/accounts/login_en/')
def activity_mem_en(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)

        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/activity_mem_en/')

    else:
        form = EditMessageForm()

        activities = Activity.objects.all()

        args = {'form': form, 'activities': activities}

        return render(request, 'home/activity_mem_en.html', args)


@login_required(login_url='/accounts/login_ar/')
def activity_mem_ar(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)

        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/activity_mem_ar/')

    else:
        form = EditMessageForm()

        activities = Activity.objects.all()

        args = {'form': form, 'activities': activities}

        return render(request, 'home/activity_mem_ar.html', args)


# mem views


@login_required(login_url='/accounts/login_en/')
def mem_en(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)

        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)

        msg_obj.save()

        return redirect('/accounts/profile_en/')

    else:
        user_profile = UserProfile.objects.get(user=request.user)

        form = EditMessageForm()

        args = {'user': request.user, 'user_profile': user_profile, 'form': form}

        return render(request, 'home/mem_en.html', args)


@login_required(login_url='/accounts/login_ar/')
def mem_ar(request):
    if request.method == 'POST':
        form = EditMessageForm(request.POST)

        content = request.POST.get('message', '')

        user_profile = UserProfile.objects.get(user=request.user)
        sender_name = user_profile.mem_first_name_en + ' ' + user_profile.mem_mid_name_en + ' ' + user_profile.mem_last_name_en
        sender_email = request.user.email

        msg_obj = Message(msg_sender_name=sender_name, msg_sender_email=sender_email, msg_content=content)
        msg_obj.save()

        return redirect('/accounts/profile_ar/')

    else:
        user_profile = UserProfile.objects.get(user=request.user)

        form = EditMessageForm()

        args = {'user': request.user, 'user_profile': user_profile, 'form': form}

        return render(request, 'home/mem_ar.html', args)


# edit_user_profile views


@login_required(login_url='/accounts/login_en/')
def edit_user_profile_en(request):
    if request.method == 'POST':
        form = EditUserProfileForm(request.POST)

        fna = request.POST.get('first_name_ar', '')
        fne = request.POST.get('first_name_en', '')
        mna = request.POST.get('mid_name_ar', '')
        mne = request.POST.get('mid_name_en', '')
        lna = request.POST.get('last_name_ar', '')
        lne = request.POST.get('last_name_en', '')
        uid = request.POST.get('uid', '')
        ma = request.POST.get('major_ar', '')
        me = request.POST.get('major_en', '')
        #email = request.POST.get('email', '')
        phone = request.POST.get('phone', '')

        user_profile = UserProfile.objects.get(user=request.user)

        if fna:
            user_profile.mem_first_name_ar = fna

        if fne:
            user_profile.mem_first_name_en = fne

        if mna:
            user_profile.mem_mid_name_ar = mna

        if mne:
            user_profile.mem_mid_name_en = mne

        if lna:
            user_profile.mem_last_name_ar = lna

        if lne:
            user_profile.mem_last_name_en = lne

        if uid:
            user_profile.mem_uid = uid

        if ma:
            user_profile.mem_major_ar = ma

        if me:
            user_profile.mem_major_en = me

        #request.user.email = email

        if phone:
            user_profile.mem_phone = phone

        #request.user.save()
        user_profile.save()

        return redirect('/accounts/profile_en/')

    else:
        form = EditUserProfileForm()

        return render(request, 'home/edit_user_profile_en.html', {'form': form})


@login_required(login_url='/accounts/login_ar/')
def edit_user_profile_ar(request):
    if request.method == 'POST':
        form = EditUserProfileForm(request.POST)

        fna = request.POST.get('first_name_ar', '')
        fne = request.POST.get('first_name_en', '')
        mna = request.POST.get('mid_name_ar', '')
        mne = request.POST.get('mid_name_en', '')
        lna = request.POST.get('last_name_ar', '')
        lne = request.POST.get('last_name_en', '')
        uid = request.POST.get('uid', '')
        ma = request.POST.get('major_ar', '')
        me = request.POST.get('major_en', '')
        #email = request.POST.get('email', '')
        phone = request.POST.get('phone', '')

        user_profile = UserProfile.objects.get(user=request.user)

        if fna:
            user_profile.mem_first_name_ar = fna

        if fne:
            user_profile.mem_first_name_en = fne

        if mna:
            user_profile.mem_mid_name_ar = mna

        if mne:
            user_profile.mem_mid_name_en = mne

        if lna:
            user_profile.mem_last_name_ar = lna

        if lne:
            user_profile.mem_last_name_en = lne

        if uid:
            user_profile.mem_uid = uid

        if ma:
            user_profile.mem_major_ar = ma

        if me:
            user_profile.mem_major_en = me

        #request.user.email = email

        if phone:
            user_profile.mem_phone = phone

        #request.user.save()
        user_profile.save()

        return redirect('/accounts/profile_ar/')

    else:
        form = EditUserProfileForm()

        return render(request, 'home/edit_user_profile_ar.html', {'form': form})


# change_password views


@login_required(login_url='/accounts/login_en/')
def change_password_en(request):
    if request.method == 'POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)

            return redirect('/accounts/profile_en/edit_user_profile_en/')

        else:
            return redirect(reverse('home:change_password_en'))

    else:
        form = PasswordChangeForm(user=request.user)

        args = {'form': form}

        return render(request, 'home/change_password_en.html', args)


@login_required(login_url='/accounts/login_ar/')
def change_password_ar(request):
    if request.method == 'POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)

            return redirect('/accounts/profile_ar/edit_user_profile_ar/')

        else:
            return redirect(reverse('home:change_password_ar'))

    else:
        form = PasswordChangeForm(user=request.user)

        args = {'form': form}

        return render(request, 'home/change_password_ar.html', args)


# password-reset-views


class SaltMixin(object):
    salt = 'password_recovery'
    url_salt = 'password_recovery_url'


def loads_with_timestamp(value, salt):
    """Returns the unsigned value along with its timestamp, the time when it
    got dumped."""
    try:
        signing.loads(value, salt=salt, max_age=-999999)
    except signing.SignatureExpired as e:
        age = float(str(e).split('Signature age ')[1].split(' >')[0])
        timestamp = timezone.now() - datetime.timedelta(seconds=age)
        return timestamp, signing.loads(value, salt=salt)


class RecoverDone(SaltMixin, generic.TemplateView):
    template_name = 'home/reset_sent.html'

    def get_context_data(self, **kwargs):
        ctx = super(RecoverDone, self).get_context_data(**kwargs)
        try:
            ctx['timestamp'], ctx['email'] = loads_with_timestamp(
                self.kwargs['signature'], salt=self.url_salt,
            )
        except signing.BadSignature:
            raise Http404
        return ctx


recover_done = RecoverDone.as_view()


class Recover(SaltMixin, generic.FormView):
    case_sensitive = True
    form_class = PasswordRecoveryForm
    template_name = 'home/recovery_form.html'
    success_url_name = 'password_reset_sent'
    email_template_name = 'home/recovery_email.txt'
    email_subject_template_name = 'home/recovery_email_subject.txt'
    search_fields = ['username', 'email']

    def get_success_url(self):
        return reverse(self.success_url_name, args=[self.mail_signature])

    def get_context_data(self, **kwargs):
        kwargs['url'] = self.request.get_full_path()
        return super(Recover, self).get_context_data(**kwargs)

    def get_form_kwargs(self):
        kwargs = super(Recover, self).get_form_kwargs()
        kwargs.update({
            'case_sensitive': self.case_sensitive,
            'search_fields': self.search_fields,
        })
        return kwargs

    def get_site(self):
        return get_current_site(self.request)

    def send_notification(self):
        context = {
            'site': self.get_site(),
            'user': self.user,
            'username': self.user.get_username(),
            'token': signing.dumps(self.user.pk, salt=self.salt),
            'secure': self.request.is_secure(),
        }
        body = loader.render_to_string(self.email_template_name,
                                       context).strip()
        subject = loader.render_to_string(self.email_subject_template_name,
                                          context).strip()
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL,
                  [self.user.email])

    def form_valid(self, form):
        self.user = form.cleaned_data['user']
        self.send_notification()
        if (
            len(self.search_fields) == 1 and
            self.search_fields[0] == 'username'
        ):
            # if we only search by username, don't disclose the user email
            # since it may now be public information.
            email = self.user.username
        else:
            email = self.user.email
        self.mail_signature = signing.dumps(email, salt=self.url_salt)
        return super(Recover, self).form_valid(form)


recover = Recover.as_view()


class Reset(SaltMixin, generic.FormView):
    form_class = PasswordResetForm
    token_expires = None
    template_name = 'home/reset.html'
    success_url = reverse_lazy('password_reset_done')

    def get_token_expires(self):
        duration = getattr(settings, 'PASSWORD_RESET_TOKEN_EXPIRES',
                           self.token_expires)
        if duration is None:
            duration = 3600 * 48  # Two days
        return duration

    @method_decorator(sensitive_post_parameters('password1', 'password2'))
    def dispatch(self, request, *args, **kwargs):
        self.request = request
        self.args = args
        self.kwargs = kwargs
        self.user = None

        try:
            pk = signing.loads(kwargs['token'],
                               max_age=self.get_token_expires(),
                               salt=self.salt)
        except signing.BadSignature:
            return self.invalid()

        self.user = get_object_or_404(get_user_model(), pk=pk)
        return super(Reset, self).dispatch(request, *args, **kwargs)

    def invalid(self):
        return self.render_to_response(self.get_context_data(invalid=True))

    def get_form_kwargs(self):
        kwargs = super(Reset, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super(Reset, self).get_context_data(**kwargs)
        if 'invalid' not in ctx:
            ctx.update({
                'username': self.user.get_username(),
                'token': self.kwargs['token'],
            })
        return ctx

    def form_valid(self, form):
        form.save()
        user_recovers_password.send(
            sender=get_user_model(),
            user=form.user,
            request=self.request
        )
        return redirect(self.get_success_url())


reset = Reset.as_view()


class ResetDone(generic.TemplateView):
    template_name = 'home/recovery_done.html'


reset_done = ResetDone.as_view()
