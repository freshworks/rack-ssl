require 'rack'
require 'rack/request'

module Rack
  class SSL

    def initialize(app, options = {})
      @app = app

      @hsts = options[:hsts]
      # @hsts = {} if @hsts.nil? || @hsts == true
      # @hsts = self.class.default_hsts_options.merge(@hsts) if @hsts

      @exclude = options[:exclude]
      @host    = options[:host]
    end

    def call(env)
      req = Request.new(env)
      if req.protocol == 'https://'
        status, headers, body = @app.call(env)
        # headers = hsts_headers.merge(headers)
        flag_cookies_as_secure!(headers)
        [status, headers, body]
      else
        status, headers, body = @app.call(env)
        remove_hsts_headers
        [status, headers, body]
      end
    end

    private

      # http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02
      def hsts_headers
        if @hsts
          value = "max-age=#{@hsts[:expires]}"
          value += "; includeSubDomains" if @hsts[:subdomains]
          { 'Strict-Transport-Security' => value }
        else
          {}
        end
      end

      def remove_hsts_headers

      end

      def flag_cookies_as_secure!(headers)
        if cookies = headers['Set-Cookie']
          # Rack 1.1's set_cookie_header! will sometimes wrap
          # Set-Cookie in an array
          unless cookies.respond_to?(:to_ary)
            cookies = cookies.split("\n")
          end

          headers['Set-Cookie'] = cookies.map { |cookie|
            if cookie !~ /; secure(;|$)/
              "#{cookie}; secure"
            else
              cookie
            end
          }.join("\n")
        end
      end
  end
end
