module RailsAuth
	class Logger
		include Singleton

		def initialize
			@logger = RailsAuth.config.logger
		end

		def log(name, *opts)
			if !@logger.nil?
				@logger.send(name,opts.first)
			end
		end

		alias method_missing log
	end
end
