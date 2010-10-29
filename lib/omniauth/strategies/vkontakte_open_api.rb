require 'omniauth/vkontakte'
require 'omniauth/strategies/vkontakte_open_api/view_helper'

module OmniAuth
  class Configuration
    attr_accessor :vkontakte_app_id
    attr_accessor :vkontakte_app_secret
  end
end

module OmniAuth
  module Strategies
    class VkontakteOpenApi
      include OmniAuth::Strategy
      include ViewHelper::PageHelper

      def initialize(app, app_id, app_secret, options = {})
        @options = options
        OmniAuth.config.vkontakte_app_id = app_id
        OmniAuth.config.vkontakte_app_secret = app_secret
        super(app, :vkontakte_open_api)
      end

      attr_reader :app_id, :app_secret
      
      protected
      
      def request_phase
        Rack::Response.new(vkontakte_login_page).finish
      end
      
      def callback_phase
        app_cookie = request.cookies['vk_app_' + OmniAuth.config.vkontakte_app_id]
        if app_cookie.nil?
          fail!(:invalid_credentials)
        else
          sig = Digest::MD5.new.hexdigest(app_cookie.split('&').sort[0..3].join('') + OmniAuth.config.vkontakte_app_secret) == app_cookie.split('&')[-1].split('=')[1]
          if sig
            super
          else
            fail!(:invalid_credentials)
          end
        end
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super(), {
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
    end
  end
end
