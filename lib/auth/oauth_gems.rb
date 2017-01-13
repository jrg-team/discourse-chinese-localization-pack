require 'omniauth/strategies/oauth2'

# Various OAuth gems are inline because of deployment difficulties
# gem 'omniauth-douban-oauth2' 0.0.7; https://github.com/liluo/omniauth-douban-oauth2
# part of gem 'omniauth-qq' 0.3.0; https://github.com/beenhero/omniauth-qq
# gem 'omniauth-renren-oauth2' 0.0.6; https://github.com/yeeli/omniauth-renren-oauth2
# firstly import from gem 'omniauth-weibo-oauth2' 5108f7b318fb014b9778dddd3bfee9a2d5007996; https://github.com/beenhero/omniauth-weibo-oauth2
# now modified and managed by Erick Guan

class OmniAuth::Strategies::Douban < OmniAuth::Strategies::OAuth2
  DEFAULT_SCOPE = 'douban_basic_common,shuo_basic_r,shuo_basic_w'

  option :name, 'douban'

  option :client_options, {
    :site          => 'https://api.douban.com',
    :authorize_url => 'https://www.douban.com/service/auth2/auth',
    :token_url     => 'https://www.douban.com/service/auth2/token'
  }

  option :token_params, {
    :parse => :json,
  }

  uid do
    raw_info['id']
  end

  info do
    {
      :name        => raw_info['name'],
      :nickname    => raw_info['uid'],
      :location    => raw_info['loc_name'],
      :image       => raw_info['avatar'],
      :urls        => {:alt => raw_info['alt']},
      :description => raw_info['desc'],
    }
  end

  extra do
    { :raw_info => raw_info }
  end

  def raw_info
    access_token.options[:param_name] = 'access_token'
    @raw_info ||= access_token.get("/v2/user/~me").parsed
  rescue ::Timeout::Error => e
    raise e
  end

  def authorize_params
    super.tap do |params|
      params[:scope] = request.params['scope'] || params[:scope] || DEFAULT_SCOPE
    end
  end
end

class OmniAuth::Strategies::Qq < OmniAuth::Strategies::OAuth2
  option :name, "qq"

  option :client_options, {
    :site => 'https://graph.qq.com/oauth2.0/',
    :authorize_url => '/oauth2.0/authorize',
    :token_url => "/oauth2.0/token"
  }

  option :token_params, {
    :state => 'foobar',
    :parse => :query
  }

  uid do
    @uid ||= begin
      access_token.options[:mode] = :query
      access_token.options[:param_name] = :access_token
      # Response Example: "callback( {\"client_id\":\"11111\",\"openid\":\"000000FFFF\"} );\n"
      response = access_token.get('/oauth2.0/me')
      #TODO handle error case
      matched = response.body.match(/"openid":"(?<openid>\w+)"/)
      matched[:openid]
    end
  end

  info do
    {
      :nickname => raw_info['nickname'],
      :name => raw_info['nickname'],
      :image => raw_info['figureurl_1'],
    }
  end

  extra do
    {
      :raw_info => raw_info
    }
  end

  def raw_info
    @raw_info ||= begin
                    #TODO handle error case
                    #TODO make info request url configurable
      client.request(:get, "https://graph.qq.com/user/get_user_info", :params => {
        :format => :json,
        :openid => uid,
        :oauth_consumer_key => options[:client_id],
        :access_token => access_token.token
      }, :parse => :json).parsed
    end
  end
end

class OmniAuth::Strategies::Renren < OmniAuth::Strategies::OAuth2
  option :client_options, {
    :site => 'http://graph.renren.com',
    :authorize_url => '/oauth/authorize',
    :token_url => '/oauth/token'
  }

  uid { raw_info['id'] }

  info do
    {
      :name => raw_info['name'],
      :nickname => raw_info['name'],
      :image => raw_info['avatar'][0]['url'],
      :urls => {
        'Renren' => "http://www.renren.com/#{raw_info["id"]}/profile"
      }
    }
  end

  extra do
    {
      :raw_info => raw_info
    }
  end

  def raw_info
    access_token.options[:mode] = :query
    access_token.options[:param_name] = 'access_token'
    @uid ||= access_token.get("https://api.renren.com/v2/user/login/get").parsed['response']['id']
    @raw_info ||= access_token.get("https://api.renren.com/v2/user/get", :params => {'userId' => @uid}).parsed['response']
  rescue
    {'id' => nil, 'avatar' => [{'url' => ''}], 'name' => nil}
  end
end

class OmniAuth::Strategies::Weibo < OmniAuth::Strategies::OAuth2
  option :client_options, {
    :site           => "https://api.weibo.com",
    :authorize_url  => "/oauth2/authorize",
    :token_url      => "/oauth2/access_token",
    :token_method => :post
  }
  option :token_params, {
    :parse          => :json
  }

  uid do
    raw_info['id']
  end

  info do
    {
      :nickname     => raw_info['screen_name'],
      :name         => raw_info['name'],
      :location     => raw_info['location'],
      :image        => image_url,
      :description  => raw_info['description'],
      :urls => {
        'Blog'      => raw_info['url'],
        'Weibo'     => raw_info['domain'].present?? "http://weibo.com/#{raw_info['domain']}" : "http://weibo.com/u/#{raw_info['id']}",
      }
    }
  end

  extra do
    {
      :raw_info => raw_info
    }
  end

  def raw_info
    access_token.options[:mode] = :query
    access_token.options[:param_name] = 'access_token'
    @uid ||= access_token.get('/2/account/get_uid.json').parsed["uid"]
    @raw_info ||= access_token.get("/2/users/show.json", :params => {:uid => @uid}).parsed
  end

  def find_image
    raw_info[%w(avatar_hd avatar_large profile_image_url).find { |e| raw_info[e].present? }]
  end

  #url:                 option:   size:
  #avatar_hd            original  original_size
  #avatar_large         large     180x180
  #profile_image_url    middle    50x50
  #                     small     30x30
  #default is middle
  def image_url
    case (options[:image_size] || '').to_sym
      when :original
        url = raw_info['avatar_hd']
      when :large
        url = raw_info['avatar_large']
      when :small
        url = raw_info['avatar_large'].sub('/180/','/30/')
      else
        url = raw_info['profile_image_url']
    end
  end

  ##
  # You can pass +display+, +with_offical_account+ or +state+ params to the auth request, if
  # you need to set them dynamically. You can also set these options
  # in the OmniAuth config :authorize_params option.
  #
  # /auth/weibo?display=mobile&with_offical_account=1
  #
  def authorize_params
    super.tap do |params|
      %w[display with_offical_account forcelogin].each do |v|
        if request.params[v]
          params[v.to_sym] = request.params[v]
        end
      end
    end
  end
end

class OmniAuth::Strategies::Jirengu < OmniAuth::Strategies::OAuth2
  option :client_options, {
    :site => 'http://user.jirengu.com',
    :authorize_url => '/oauth/authorize',
    :token_url => '/oauth/token'
  }

  uid do
    raw_info['uid'].to_s
  end

  info do
    {
      'name' => raw_info['name'],
      'image' => raw_info['avatar'],
      'email' => raw_info['email'],
    }
  end

  extra do
    {
      :raw_info => raw_info
    }
  end

  def raw_info
    access_token.options[:mode] = :query
    @raw_info ||= access_token.get("/api/v1/me.json").parsed
  end


  def authorize_params
    super.tap do |params|
      %w[scope client_options].each do |v|
        if request.params[v]
          params[v.to_sym] = request.params[v]
        end
      end
    end
  end
end
