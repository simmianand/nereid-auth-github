# -*- coding: utf-8 -*-
"""
    user

    Github based user authentication code

    :copyright: (c) 2012-2013 by Openlabs Technologies & Consulting (P) LTD
    :license: GPLv3, see LICENSE for more details.
"""
from nereid import url_for, flash, redirect, current_app
from nereid.globals import session, request
from nereid.signals import login, failed_login
from flask.ext.oauth import OAuth
from trytond.model import fields
from trytond.pool import PoolMeta
import requests

from .i18n import _


__all__ = ['Website', 'NereidUser']
__metaclass__ = PoolMeta


class Website:
    """Add Github settings"""
    __name__ = "nereid.website"

    github_id = fields.Char("Github client ID")
    github_secret = fields.Char("Github Client Secret")

    def get_github_oauth_client(self, scope='', token='github_oauth_token'):
        """
        Returns a instance of Github OAuth
        """
        if not all([self.github_id, self.github_secret]):
            current_app.logger.error("Github api settings are missing")
            flash(_("Github login is not available at the moment"))
            return None

        oauth = OAuth()
        github = oauth.remote_app(
            'github',
            base_url='https://github.com',
            request_token_url=None,
            access_token_url='/login/oauth/access_token',
            authorize_url='/login/oauth/authorize',
            consumer_key=self.github_id,
            consumer_secret=self.github_secret,
            request_token_params={'scope': scope},
            access_token_method="POST",
        )
        github.tokengetter_func = lambda *a: session.get(token)
        return github


class NereidUser:
    "Nereid User"
    __name__ = "nereid.user"

    github_id = fields.Integer('Github ID')
    github_url = fields.Char('Github URL')

    @classmethod
    def github_login(cls):
        """
        The URL to which a new request to authenticate to github begins
        Usually issues a redirect.
        """
        github = request.nereid_website.get_github_oauth_client()
        if github is None:
            return redirect(
                request.referrer or url_for('nereid.website.login')
            )
        return github.authorize(
            callback=url_for(
                'nereid.user.github_authorized_login',
                next=request.args.get('next') or request.referrer or None,
                _external=True
            )
        )

    @classmethod
    def github_authorized_login(cls):
        """
        Authorized handler to which github will redirect the user to
        after the login attempt is made.
        """
        github = request.nereid_website.get_github_oauth_client()
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
            failed_login.send(form=data)
            return redirect(url_for('nereid.website.login'))

        # Write the oauth token to the session
        session['github_oauth_token'] = data['access_token']

        # Find the information from facebook
        me = requests.get(
            'https://api.github.com/user',
            params={'access_token': session['github_oauth_token']}
        ).json

        # Find the user
        users = cls.search([
            ('email', '=', me['email']),
            ('company', '=', request.nereid_website.company.id),
        ])
        if not users:
            current_app.logger.debug(
                "No Github user with email %s" % me['email']
            )
            current_app.logger.debug(
                "Registering new user %s" % me['name']
            )
            user, = cls.create([{
                'name': me['name'],
                'display_name': me['name'],
                'email': me['email'],
                'github_id': me['id'],
                'addresses': False,
                'github_url': me['html_url'],
            }])
            flash(
                _('Thanks for registering with us using github')
            )
        else:
            user, = users

        # Add the user to session and trigger signals
        session['user'] = user.id
        if not user.github_id:
            cls.write(
                [user], {
                    'github_id': me['id'],
                    'github_url': me['html_url']
                }
            )
        flash(_("You are now logged in. Welcome %(name)s", name=user.name))
        login.send()
        if request.is_xhr:
            return 'OK'
        return redirect(
            request.values.get(
                'next', url_for('nereid.website.home')
            )
        )
