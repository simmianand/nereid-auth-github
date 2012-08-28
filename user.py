# -*- coding: utf-8 -*-
"""
    user

    Github based user authentication code

    :copyright: (c) 2012 by Openlabs Technologies & Consulting (P) LTD
    :license: GPLv3, see LICENSE for more details.
"""
from nereid import url_for, flash, redirect, current_app
from nereid.globals import session, request
from nereid.signals import login, failed_login
from flaskext.oauth import OAuth
from trytond.model import ModelSQL, ModelView, fields
from trytond.pool import Pool
import requests

from .i18n import _


class Website(ModelSQL, ModelView):
    """Add Github settings"""
    _name = "nereid.website"

    github_id = fields.Char("Github client ID")
    github_secret = fields.Char("Github Client Secret")

    def get_github_oauth_client(self, site=None,
            scope='', token='github_oauth_token'):
        """Returns a instance of LinkedIn OAuth

        :param site: Browserecord of the website, If not specified, it will be
                     guessed from the request context
        """
        if site is None:
            site = request.nereid_website

        if not all([site.github_id, site.github_secret]):
            current_app.logger.error("Github api settings are missing")
            flash(_("Github login is not available at the moment"))
            return None

        oauth = OAuth()
        github = oauth.remote_app('github',
            base_url='https://github.com',
            request_token_url=None,
            access_token_url='/login/oauth/access_token',
            authorize_url='/login/oauth/authorize',
            consumer_key=site.github_id,
            consumer_secret=site.github_secret,
            request_token_params={'scope': scope},
            access_token_method="POST",
        )
        github.tokengetter_func = lambda *a: session.get(token)
        return github

Website()


class NereidUser(ModelSQL, ModelView):
    "Nereid User"
    _name = "nereid.user"

    github_id = fields.Integer('Github ID')
    github_url = fields.Char('Github URL')

    def github_login(self):
        """The URL to which a new request to authenticate to linedin begins
        Usually issues a redirect.
        """
        website_obj = Pool().get('nereid.website')

        github = website_obj.get_github_oauth_client()
        if github is None:
            return redirect(
                request.referrer or url_for('nereid.website.login')
            )
        return github.authorize(
            callback = url_for('nereid.user.github_authorized_login',
                next = request.args.get('next') or request.referrer or None,
                _external = True
            )
        )

    def github_authorized_login(self):
        """Authorized handler to which github will redirect the user to
        after the login attempt is made.
        """
        website_obj = Pool().get('nereid.website')

        github = website_obj.get_github_oauth_client()
        if github is None:
            return redirect(
                request.referrer or url_for('nereid.website.login')
            )


        try:
            # The response is an oauth2 response with code. But Github API
            # requires the
            if 'oauth_verifier' in request.args:
                data = github.handle_oauth1_response()
            elif 'code' in request.args:
                data = github.handle_oauth2_response()
            else:
                data = github.handle_unknown_response()
            github.free_request_token()
        except Exception, exc:
            raise
            current_app.logger.error("Github login failed %s" % exc)
            flash(_("We cannot talk to github at this time. Please try again"))
            return redirect(
                request.referrer or url_for('nereid.website.login')
            )

        if data is None:
            flash(
                _("Access was denied to github: %(reason)s",
                reason=request.args['error_reason'])
            )
            failed_login.send(self, form=data)
            return redirect(url_for('nereid.website.login'))

        # Write the oauth token to the session
        session['github_oauth_token'] = data['access_token']

        # Find the information from facebook
        me = requests.get(
            'https://api.github.com/user',
            params={'access_token': session['github_oauth_token']}
        ).json

        # Find the user
        user_ids = self.search([
            ('email', '=', me['email']),
            ('company', '=', request.nereid_website.company.id),
        ])
        if not user_ids:
            current_app.logger.debug(
                "No Github user with email %s" % me['email']
            )
            current_app.logger.debug(
                "Registering new user %s" % me['name']
            )
            user_id = self.create({
                'name': me['name'],
                'email': me['email'],
                'github_id': me['id'],
                'addresses': False,
                'github_url': me['html_url'],
            })
            flash(
                _('Thanks for registering with us using github')
            )
        else:
            user_id, = user_ids

        # Add the user to session and trigger signals
        session['user'] = user_id
        user = self.browse(user_id)
        if not user.github_id:
            self.write(
                user_id, {
                    'github_id': me['id'],
                    'github_url': me['html_url']
                }
            )
        flash(_("You are now logged in. Welcome %(name)s", name=user.name))
        login.send(self)
        if request.is_xhr:
            return 'OK'
        return redirect(
            request.values.get(
                'next', url_for('nereid.website.home')
            )
        )


NereidUser()
