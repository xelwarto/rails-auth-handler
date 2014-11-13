
module RailsAuth
  module Handler

    def verify_auth
      RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):Authenticating user request'
      c = RailsAuth.config

      if !c.dev_mode.nil? && c.dev_mode
        RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):Development mode enabled - Authentication bypassed'
        session[c.session_user.to_sym] = c.dev_user
        session[c.session_dn.to_sym] = c.dev_dn
        session[c.session_mail.to_sym] = c.dev_mail

        auth_valid
      else
        RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):Validating user authentication information'

        if verify_token
          RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):SSO token validation successful'
          sso_id = verify_user

          if sso_id.nil?
            RailsAuth.logger.error 'RailsAuth::Handler(verify_auth):error retrieving SSO id'
            send_error
          else
            id = session[c.session_user.to_sym]

            if id.nil?
              RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):session user id not found'

              build_session sso_id
              id = session[c.session_user.to_sym]

              if id.nil?
                RailsAuth.logger.error "RailsAuth::Handler(verify_auth):session information is invalid for: #{sso_id}"
                send_error
              else
                auth_valid
              end
            else
              if id == sso_id
                build_session sso_id if session[c.session_dn.to_sym].nil?
                build_session sso_id if session[c.session_mail.to_sym].nil?

                id = session[c.session_user.to_sym]
                if id.nil?
                  RailsAuth.logger.error "RailsAuth::Handler(verify_auth):session information is invalid for: #{sso_id}"
                  send_error
                else
                  auth_valid
                end
              else
                RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):invalid session user id'
                send_login
              end
            end

          end
        else
          RailsAuth.logger.debug 'RailsAuth::Handler(verify_auth):SSO token validation failed'
          send_login
        end
      end

      return false
    end

    def build_session(id=nil)
      RailsAuth.logger.debug "RailsAuth::Handler(build_session):Building user session information for: #{id}"
      c = RailsAuth.config

      session[c.session_user.to_sym] = nil
      session[c.session_dn.to_sym] = nil
      session[c.session_mail.to_sym] = nil

      if id.nil?
        RailsAuth.logger.error 'RailsAuth::Handler(build_session):session id is invalid'
      else
        begin
          RailsAuth.logger.debug 'RailsAuth::Handler(build_session):Searching LDAP for user information'
          Ext::LDAP.user_from_uid uid: id, attributes: ['uid','mail'] do |ent|
            if !ent.nil?

              if !ent.dn.nil?
                session[c.session_dn.to_sym] = ent.dn.to_s
              else
                rasie Exception.new "LDAP account DN invalid for: #{id}"
              end

              if !ent.first(:mail).nil?
                session[c.session_mail.to_sym] = ent.first(:mail).to_s
              else
                rasie Exception.new "LDAP account email address invalid for: #{id}"
              end

              if !ent.first(:uid).nil?
                session[c.session_user.to_sym] = ent.first(:uid).to_s
              else
                rasie Exception.new "LDAP account user id invalid for: #{id}"
              end

            end
          end
        rescue Exception => e
          RailsAuth.logger.error "RailsAuth::Handler(build_session):#{e}"
          session[c.session_user.to_sym] = nil
          session[c.session_dn.to_sym] = nil
          session[c.session_mail.to_sym] = nil
        end
      end
    end

    def verify_token
      RailsAuth.logger.debug 'RailsAuth::Handler(verify_token):Validating SSO token'
      auth = OpenAM::Auth::API.instance

      token_valid = false
      token = cookies[auth.cookie_name.to_sym]

      if !token.nil?
        RailsAuth.logger.debug "RailsAuth::Handler(verify_token):SSO token set to: #{token}"

        begin
          RailsAuth.logger.debug 'RailsAuth::Handler(verify_token):Verifying if token is valid'
          token_valid = auth.verify_token token
        rescue Exception => e
          RailsAuth.logger.error "RailsAuth::Handler(verify_token):#{e}"
          token_valid = false
        end
      end

      return token_valid
    end

    def verify_user
      RailsAuth.logger.debug 'RailsAuth::Handler(verify_user):Verifying SSO session user information'
      auth = OpenAM::Auth::API.instance

      sso_id = nil
      token = cookies[auth.cookie_name.to_sym]

      if !token.nil?
        RailsAuth.logger.debug "RailsAuth::Handler(verify_user):SSO token set to: #{token}"

        sso_user_info = nil
        begin
          RailsAuth.logger.debug 'RailsAuth::Handler(verify_user):Retrieving SSO session user information'
          sso_user_info = auth.user_info token
        rescue Exception => e
          RailsAuth.logger.error "RailsAuth::Handler(verify_user):#{e}"
          sso_user_info = nil
        end

        if !sso_user_info.nil?
          if !sso_user_info[:id].nil?
            sso_id = sso_user_info[:id]
            RailsAuth.logger.debug "RailsAuth::Handler(verify_user):SSO session user id found: #{sso_id}"
          end
        end
      end

      sso_id
    end

    def auth_login(opts=nil)
      auth = OpenAM::Auth::API.instance
    end

    def auth_logout
      RailsAuth.logger.debug 'RailsAuth::Handler(auth_logout):Attemtping to logout SSO session'
      auth = OpenAM::Auth::API.instance

      token = cookies[auth.cookie_name.to_sym]

      if !token.nil?
        RailsAuth.logger.debug "RailsAuth::Handler(auth_logout):SSO token set to: #{token}"

        begin
          RailsAuth.logger.debug 'RailsAuth::Handler(auth_logout):Sending logout API request'
          logout = auth.logout token
          if !logout.nil? && logout.result =~ /success/i
            RailsAuth.logger.debug 'RailsAuth::Handler(auth_logout):Logout Successful'

            RailsAuth.logger.debug 'RailsAuth::Handler(auth_logout):Removing SSO cookie'
            cookies.delete(auth.cookie_name.to_sym)
            return true
          end
        rescue Exception => e
          RailsAuth.logger.error "RailsAuth::Handler(auth_logout):#{e}"
        end
      else
        RailsAuth.logger.error 'RailsAuth::Handler(auth_logout):invalid SSO token'
      end

      return false
    end

    def send_login
      RailsAuth.logger.debug 'RailsAuth::Handler(send_login):redirecting user to SSO login'
      auth = OpenAM::Auth::API.instance

      begin
        RailsAuth.logger.debug 'RailsAuth::Handler(send_login):resetting application session'
        reset_session

        login_url = auth.login_url request.url
        RailsAuth.logger.debug "RailsAuth::Handler(send_login):redirecting to: #{login_url}"
        redirect_to login_url
      rescue Exception => e
        RailsAuth.logger.error "RailsAuth::Handler(send_login):#{e}"
        send_error
      end
    end

    def auth_valid
    end

    def send_error
      raise Exception.new 'RailsAuth::Handler(send_error):Authentication failed with error'
    end

  end
end
