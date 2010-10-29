require 'omniauth/vkontakte'
require 'omniauth/strategies/vkontakte/view_helper'
require 'digest/md5'

module OmniAuth
  class Configuration
    attr_accessor :vkontakte_app_id
  end
end

module OmniAuth
  module Strategies
    class Vkontakte
      include OmniAuth::Strategy
      include ViewHelper::PageHelper
      attr_accessor :app_id, :app_secret
      
      class CallbackError < StandardError
        attr_accessor :error, :error_reason
        def initialize(error=nil, error_reason='')
          self.error = error
          self.error_reason = error_reason
        end
      end

      def initialize(app, app_id, app_secret, options = {})
        super(app, :vkontakte)
        @options = options
        OmniAuth.config.vkontakte_app_id = @app_id = app_id
        @app_secret = app_secret
      end
      
      protected
      
      def request_phase
        Rack::Response.new(vkontakte_login_page).finish
      end
      
      def callback_phase
        app_cookie = request.cookies['vk_app_' + app_id]
        
        raise CallbackError.new if app_cookie.nil?
        
        valid = vkontakte_sign(app_cookie) == app_cookie.split('&')[-1].split('=')[1]

        raise CallbackError.new if !valid

        super
      rescue CallbackError => e
        fail!(:invalid_response, e)
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => request[:uid],
          'user_info' => {
            'nickname' => request[:nickname],
            'name' => "#{request[:first_name]} #{request[:last_name]}",
            'first_name' => request[:first_name],
            'last_name' => request[:last_name],
            'image' => request[:photo],
            'urls' => { 'Page' => 'http://vkontakte.ru/id' + request[:uid] }
          }
        })
      end
      
      def vkontakte_sign(params)
        Digest::MD5.new.hexdigest(params.split('&').sort[0..3].join('') + app_secret)
      end
      
    end
  end
end
