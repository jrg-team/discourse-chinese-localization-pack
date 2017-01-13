class JirenguAuthenticator < ::Auth::Authenticator
  AUTHENTICATOR_NAME = 'jirengu'.freeze

  def name
    AUTHENTICATOR_NAME
  end

  def after_authenticate(auth_token)
    result = Auth::Result.new

    data = auth_token[:info]
    email = auth_token[:info][:email]
    raw_info = auth_token[:extra][:raw_info]
    jirengu_uid = auth_token[:uid]

    current_info = ::PluginStore.get(AUTHENTICATOR_NAME, "jirengu_uid_#{jirengu_uid}")

    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    else
      current_info = Hash.new
    end
    current_info.store(:raw_info, raw_info)
    ::PluginStore.set(AUTHENTICATOR_NAME, "jirengu_uid_#{jirengu_uid}", current_info)

    result.name = data['name']
    result.username = data['nickname']
    result.email = email

    result.extra_data = { jirengu_uid: jirengu_uid }

    result
  end

  def after_create_account(user, auth)
    jirengu_uid = auth[:extra_data][:jirengu_uid]
    current_info = ::PluginStore.get(AUTHENTICATOR_NAME, "jirengu_uid_#{jirengu_uid}") || {}
    ::PluginStore.set(AUTHENTICATOR_NAME, "jirengu_uid_#{jirengu_uid}", current_info.merge(user_id: user.id))
  end

  def register_middleware(omniauth)
    omniauth.provider :jirengu, setup: lambda { |env|
      strategy = env['omniauth.strategy']
      strategy.options[:client_id] = SiteSetting.zh_l10n_jirengu_client_id
      strategy.options[:client_secret] = SiteSetting.zh_l10n_jirengu_client_secret
    }
  end
end
