require 'devise_couch'
require 'devise/orm/couchrest_model/date_time'
require 'orm_adapter/adapters/couchrest_model'
require 'devise/strategies/database_authenticatable'

module Devise
  module Orm
    module CouchrestModel
      module Hook
        def devise_modules_hook!
          create_authentication_views
          yield
          return
        end

        private
        def create_authentication_views

          design do
            view :by_email  # hardcoded the default devise key  TODO tj replace the old block for authentication keys
            view :by_confirmation_token
            view :by_authentication_token
            view :by_reset_password_token
            view :by_unlock_token
          end
        end
      end
    end
  end
end

module CouchRest
  module Model
    class Base
      extend ::Devise::Models
      extend ::Devise::Orm::CouchrestModel::Hook
    end
  end
end

# resource returns a view - we want a an object of type CouchRest::Model
module Devise
  module Strategies
    # Default strategy for signing in a user, based on his email and password in the database.
    class DatabaseAuthenticatable < Authenticatable
      def authenticate!
        resource = valid_password? && mapping.to.find_for_database_authentication(authentication_hash)

        ########## GET FIRST RESULT ###############
        resource = resource.first
        ##############################################

        if validate(resource){ resource.valid_password?(password) }
          resource.after_database_authentication
          success!(resource)
        elsif !halted?
          fail(:invalid)
        end
      end
    end
  end
end
