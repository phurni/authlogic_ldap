module AuthlogicLdap
  module Session
    def self.included(klass)
      klass.class_eval do
        extend Config
        include InstanceMethods
        validate :validate_by_ldap, :if => :authenticating_with_ldap?
        
        class << self
          attr_accessor :configured_ldap_password_methods
        end
      end
    end
    
    module Config
      # The host of your LDAP server.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def ldap_host(value = nil)
        rw_config(:ldap_host, value)
      end
      alias_method :ldap_host=, :ldap_host
      
      # The port of your LDAP server.
      #
      # * <tt>Default:</tt> 389
      # * <tt>Accepts:</tt> Fixnum, Integer
      def ldap_port(value = nil)
        rw_config(:ldap_port, value, 389)
      end
      alias_method :ldap_port=, :ldap_port

      # The login format (the DN for the username) where the given ldap_login
      # will replace the '%s' in the string.
      #
      # Example: "uid=%s,ou=People,o=myserver.institution.edu,o=cp"
      #
      # * <tt>Default:</tt> "%s"
      # * <tt>Accepts:</tt> String
      def ldap_login_format(value = nil)
        rw_config(:ldap_login_format, value, "%s")
      end
      alias_method :ldap_login_format=, :ldap_login_format
      
      # LDAP Encryption configuration settings. Depending on your current LDAP Server
      # you may need to setup encryption. If you set this options, you will probably
      # want to change your port to 636
      #
      # Example: ldap_use_encryption true
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def ldap_use_encryption(value = nil)
        rw_config(:ldap_use_encryption, value, false)
      end
      alias_method :ldap_use_encryption=, :ldap_use_encryption
      
      # The name of the method for storing the login/username.
      # It is the same as Authlogic::Session::Password:login_field
      # Set to the same as Authlogic::Session::Password:login_field to
      # allow authentication againts a database first.
      #
      # * <tt>Default:</tt> :ldap_login
      # * <tt>Accepts:</tt> String or Symbol
      def ldap_login_field(value = nil)
        rw_config(:ldap_login_field, value, :ldap_login)
      end
      alias_method :ldap_login_field=, :ldap_login_field
      
      # The name of the method for storing the password.
      # It is the same as Authlogic::Session::Password:password_field
      # Set to the same as Authlogic::Session::Password:password_field to
      # allow authentication againts a database first.
      #
      # * <tt>Default:</tt> :ldap_password
      # * <tt>Accepts:</tt> Symbol or String
      def ldap_password_field(value = nil)
        rw_config(:ldap_password_field, value, :ldap_password)
      end
      alias_method :ldap_password_field=, :ldap_password_field
      
      # Once LDAP authentication has succeeded we need to find the user in the database. By default this just calls the
      # find_by_ldap_login method provided by ActiveRecord. If you have a more advanced set up and need to find users
      # differently specify your own method and define your logic in there.
      #
      # For example, if you allow users to store multiple ldap logins with their account, you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.find_by_ldap_login(login)
      #       first(:conditions => ["#{LdapLogin.table_name}.login = ?", login], :join => :ldap_logins)
      #     end
      #   end
      #
      # * <tt>Default:</tt> :find_by_ldap_login
      # * <tt>Accepts:</tt> Symbol
      def find_by_ldap_login_method(value = nil)
        rw_config(:find_by_ldap_login_method, value, :find_by_smart_case_ldap_login_field)
      end
      alias_method :find_by_ldap_login_method=, :find_by_ldap_login_method
      
      # Auth against the local database before attemping to auth against the LDAP server.
      # For this to work, ldap_login_field and ldap_password_field need to have the
      # same values as login_field and password_field.
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def ldap_search_local_database_first(value = nil)
        rw_config(:ldap_search_local_database_first, value, false)
      end
      alias_method :ldap_search_local_database_first=, :ldap_search_local_database_first 
      
      # If LDAP authentication has succeeded, but the user does not exist in the database, set this to true to have
      # the the user created in the database. You NEED to provide your own method to create the user in the database.
      # By default, the method name is create_with_ldap_data. Use create_with_ldap_data_method to change.
      #
      # For example, to create the user you might do something like:
      #
      #   class User < ActiveRecord::Base
      #     def self.create_with_ldap_data(login, password, ldap_user_data)
      #       self.create(:login       => login,
      #                   :password    => password, :password_confirmation => password,
      #                   :email       => "#{user_data[:mail][0]}",
      #                   :first_name  => "#{user_data[:givenname][0]}",
      #                   :last_name   => "#{user_data[:sn][0]}")
      #     end
      #   end
      #
      # * <tt>Default:</tt> false
      # * <tt>Accepts:</tt> Boolean
      def ldap_create_in_database(value = nil)
        rw_config(:ldap_create_in_database, value, false)
      end
      alias_method :ldap_create_in_database=, :ldap_create_in_database
      
      # LDAP search base for quering for user data.
      #
      # Example: ldap_search_base "ou=People,dc=example,dc=com"
      #
      # * <tt>Default:</tt> ''
      # * <tt>Accepts:</tt> String
      def ldap_search_base(value = nil)
        rw_config(:ldap_search_base, value, '')
      end
      alias_method :ldap_search_base=, :ldap_search_base
      
      # LDAP search attribute for quering for user data.
      #
      # Example: ldap_search_attribute 'uid'
      #
      # * <tt>Default:</tt> 'uid'
      # * <tt>Accepts:</tt> String
      def ldap_search_attribute(value = nil)
        rw_config(:ldap_search_attribute, value, 'uid')
      end
      alias_method :ldap_search_attribute=, :ldap_search_attribute
      
      # User creation from LDAP data method. Use this to change the method for creating a user
      # in the local database. This must be defined in your model if ldap_create_in_database is true!
      #
      # Example: create_with_ldap_data_method :create_with_ldap_info
      #
      # * <tt>Default:</tt> :create_with_ldap_data
      # * <tt>Accepts:</tt> Symbol
      def create_with_ldap_data_method(value = nil)
        rw_config(:create_with_ldap_data_method, value, :create_with_ldap_data)
      end
      alias_method :create_with_ldap_data_method=, :create_with_ldap_data_method
    end
    
    
    module InstanceMethods
      # def self.included(klass)
      #   klass.class_eval do
      #     attr_accessor ldap_login_field
      #     attr_accessor ldap_password_field
      #     
      #     
      #   end
      #   
      #   # value = ldap_password_field
      #   # 
      # end
      
      def initialize(*args)
        if !self.class.configured_ldap_password_methods
          if ldap_login_field
            self.class.send(:attr_writer, ldap_login_field) if !respond_to?("#{ldap_login_field}=")
            self.class.send(:attr_reader, ldap_login_field) if !respond_to?(ldap_login_field)
          end
          
          if ldap_password_field
            self.class.send(:attr_writer, ldap_password_field) if !respond_to?("#{ldap_password_field}=")
            self.class.send(:define_method, ldap_password_field) {} if !respond_to?(ldap_password_field)
            
            klass.class_eval <<-"end_eval", __FILE__, __LINE__
              private
                # The password should not be accessible publicly. This way forms using form_for don't 
                # fill the password with the attempted password. To prevent this we just create this method that is private.
                def protected_#{ldap_password_field}
                  @#{ldap_password_field}
                end
            end_eval
          end
          
          self.class.configured_ldap_password_methods = true
          
        end
        
        super
      end
      
      # Hooks into credentials to print out meaningful credentials for LDAP authentication.
      def credentials
        if authenticating_with_ldap?
          details = {}
          details[ldap_login_field.to_sym] = send(ldap_login_field)
          details[ldap_password_field.to_sym] = "<protected>"
          details
        else
          super
        end
      end
      
      # Hooks into credentials so that you can pass an :ldap_login and :ldap_password key.
      def credentials=(value)
        super
        values = value.is_a?(Array) ? value : [value]
        hash = values.first.is_a?(Hash) ? values.first.with_indifferent_access : nil
        if !hash.nil?
          hash.slice(ldap_login_field, ldap_password_field).each do |field,value|
            next if value.blank?
            send("#{field}=", value)
          end
        end
      end
      
      private
        def authenticating_with_ldap?
          !ldap_host.blank? && (!send(ldap_login_field).blank? || !send(ldap_password_field).blank?)
        end
        
        def validate_by_ldap
          # If a previous authentication valided the user/pass and there are no errors, return now.
          return if ldap_search_local_database_first && errors.count == 0 && !self.attempted_record.blank? 
          
          # There were errors, or we do want to search this. Clear previous errors, or we will return
          # before checking LDAP.
          errors.clear
          errors.add(ldap_login_field, Authlogic::I18n.t('error_messages.ldap_login_blank', :default => "cannot be blank")) if send(ldap_login_field).blank?
          errors.add(ldap_password_field, Authlogic::I18n.t('error_messages.ldap_password_blank', :default => "cannot be blank")) if send("protected_#{ldap_password_field}").blank?
          return if errors.count > 0
          
          # Rescue block added because a non available server will raise a Net::LDAP::LdapError which itself is not a StandardError but an Exception
          begin
            ldap = Net::LDAP.new(:host       => ldap_host, 
                                 :port       => ldap_port, 
                                 :encryption => (:simple_tls if ldap_use_encryption) )

            ldap.auth ldap_login_format % send(ldap_login_field), send("protected_#{ldap_password_field}")
            if ldap.bind
              self.attempted_record = search_for_record(find_by_ldap_login_method, send(ldap_login_field))
              if self.attempted_record.blank?
                if ldap_create_in_database  && (user_data = fetch_user_data(send(ldap_login_field), send("protected_#{ldap_password_field}")))
                  self.attempted_record = search_for_record(create_with_ldap_data_method, send(ldap_login_field), send("protected_#{ldap_password_field}"), user_data)
                else
                  errors.add(ldap_login_field, Authlogic::I18n.t('error_messages.ldap_login_not_found', :default => "does not exist"))
                end
              end
            else
              errors.add_to_base(ldap.get_operation_result.message)
            end
          rescue Net::LDAP::LdapError => e
            errors.add_to_base(Authlogic::I18n.t("error_messages.ldap_exception.#{e.message}", :default => [:'error_messages.ldap_exception.default', e.message]))
          end
        end
        
        def fetch_user_data(login,password)
          ldap = Net::LDAP.new(:host       => ldap_host, 
                               :port       => ldap_port, 
                               :encryption => (:simple_tls if ldap_use_encryption),
                               :base       => ldap_search_base )
          ldap.authenticate(ldap_login_format % login, password)
          result = ldap.search(:filter => Net::LDAP::Filter.eq(ldap_search_attribute,login))
          result[0] if result
        end
        
        def ldap_host
          self.class.ldap_host
        end
        
        def ldap_port
          self.class.ldap_port
        end
        
        def ldap_use_encryption
          self.class.ldap_use_encryption
        end
        
        def ldap_login_format
          self.class.ldap_login_format
        end

        def ldap_login_field
          self.class.ldap_login_field
        end

        def ldap_password_field
          self.class.ldap_password_field
        end

        def find_by_ldap_login_method
          self.class.find_by_ldap_login_method
        end
        
        def ldap_search_local_database_first
          self.class.ldap_search_local_database_first
        end
        
        def ldap_create_in_database
          self.class.ldap_create_in_database
        end
        
        def ldap_search_base
          self.class.ldap_search_base
        end
        
        def ldap_search_attribute
          self.class.ldap_search_attribute
        end
        
        def create_with_ldap_data_method
          self.class.create_with_ldap_data_method
        end
        
    end
  end
end
