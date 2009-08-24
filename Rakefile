ENV['RDOCOPT'] = "-S -f html -T hanna"

require "rubygems"
require 'rake/rdoctask'

require File.dirname(__FILE__) << "/lib/authlogic_ldap/version"

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = 'authlogic-ldap'
    gem.summary = "Extension of the Authlogic library to add LDAP support."
    gem.email = "bjohnson@binarylogic.com"
    gem.homepage = "http://github.com/binarylogic/authlogic_ldap"
    gem.authors = "Ben Johnson of Binary Logic"
    gem.rubyforge_project = "authlogic-ldap"
    gem.add_dependency ["authlogic", "ruby-net-ldap"]
  end
  rescue LoadError
    puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

desc "Generate documenation for the authlogic_ldap plugin."
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'authlogic_ldap'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('TODO.rdoc')
  rdoc.rdoc_files.include('lib/**/*.rb')
end