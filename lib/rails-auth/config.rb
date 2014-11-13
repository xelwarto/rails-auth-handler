module RailsAuth
  class Config
    class << self
      def config
        @config ||= Configuration.new
      end
    end

    protected

    class Configuration
      def initialize
        @u_defined = {}
      end

      def udefine(name, *opts)
        if !name.nil?
          name = name.to_s
          if name =~ /\=\z/
            name.gsub! /\=/, ''
            if opts.size == 1
              @u_defined[name.to_sym] = opts.first
            end
          else
            @u_defined[name.to_sym]
          end
        end
      end
      alias method_missing udefine
    end
  end
end
