module AuthlogicLdap
  module ActsAsAuthentic
    def self.included(klass)
      klass.class_eval do
        extend Config
        add_acts_as_authentic_module(Methods, :prepend)
      end
    end
    
    module Config
      # The name of the ldap login field in the database.
      #
      # * <tt>Default:</tt> :ldap_login, :login, or :username, if they exist
      # * <tt>Accepts:</tt> Symbol
      def ldap_login_field(value = nil)
        rw_config(:ldap_login_field, value, first_column_to_exist(nil, :ldap_login, :login, :username))
      end
      alias_method :ldap_login_field=, :ldap_login_field
      
      # Whether or not to validate the ldap_login field. If set to false ALL ldap validation will need to be
      # handled by you.
      #
      # * <tt>Default:</tt> true
      # * <tt>Accepts:</tt> Boolean
      def validate_ldap_login(value = nil)
        rw_config(:validate_ldap_login, value, true)
      end
      alias_method :validate_ldap_login=, :validate_ldap_login
      
      def find_by_smart_case_ldap_login_field(login) #:nodoc:
        find_with_case(ldap_login_field, login)
      end
    end
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :ldap_password
          
          if validate_ldap_login
            validates_uniqueness_of :ldap_login, :scope => validations_scope, :if => :using_ldap?
            validates_presence_of :ldap_password, :if => :validate_ldap?
            validate :validate_ldap, :if => :validate_ldap?
          end
        end
      end
      
      private
        def using_ldap?
          !ldap_login.blank?
        end

        def validate_ldap
          return if errors.count > 0
          
          ldap = Net::LDAP.new(:host => ldap_host, 
                               :port => ldap_port, 
                               :encryption => (:simple_tls if ldap_use_encryption) )
          ldap.auth ldap_login, ldap_password
          errors.add_to_base(ldap.get_operation_result.message) if !ldap.bind
        end
        
        def validate_ldap?
          ldap_login_changed? && !ldap_login.blank?
        end
    end
  end
end
