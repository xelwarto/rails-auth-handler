require 'openam/auth'
require 'ext/ldap'

require 'rails-auth/version'
require 'rails-auth/handler'
require 'rails-auth/config'
require 'rails-auth/logger'

module RailsAuth
	class << self
    def config
      RailsAuth::Config.config
    end

		def logger
			@logger ||= RailsAuth::Logger.instance
		end

    def configure
      yield RailsAuth::Config.config if block_given?
    end
  end
end

RailsAuth.configure do |c|
	c.logger  			= nil

	c.dev_mode 			= false
	c.dev_user 			= nil
	c.dev_dn	 			= nil
	c.dev_mail 			= nil

	c.session_user 	= 'railsauth::session::user'
	c.session_dn 		= 'railsauth::session::dn'
	c.session_mail 	= 'railsauth::session::mail'
end
