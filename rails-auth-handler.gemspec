$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "rails-auth/version"

Gem::Specification.new do |spec|
  spec.name         = RailsAuth::NAME
  spec.version      = RailsAuth::VERSION
  spec.summary      = 'Rails OpenAM Auth Handler'
  spec.description  = ""
  spec.licenses     = ['Apache-2.0']
  spec.platform     = Gem::Platform::RUBY
  spec.authors      = [RailsAuth::AUTHOR]
  spec.email        = [RailsAuth::EMAIL]
  spec.homepage     = RailsAuth::WEBSITE

  spec.files = Dir["{app,config,db,lib}/**/*", "LICENSE", "README.md"]

  spec.add_dependency "rails", "~> 4"
end
