require 'rack'
require 'rack/request'

module Rack
  class SSL

    def initialize(app, options = {})
      @app = app
    end

    def call(env)
      req = Request.new(env)
      if req.scheme == 'https'
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
