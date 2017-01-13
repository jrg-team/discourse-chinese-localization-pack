# name: Discourse 中文本地化服务集合
# about: 为 Discourse 增加了各种本地化的功能。
# version: 0.16
# authors: Erick Guan
# url: https://github.com/fantasticfears/discourse-chinese-localization-pack

enabled_site_setting :zh_l10n_enabled

# load oauth providers
Dir[File.expand_path('../lib/auth/*.rb', __FILE__)].each { |f| require f }
require 'active_support/inflector'

# name, frame_width, frame_height, background_color, glyph
PROVIDERS = [
  ['Weibo', 920, 800, 'rgb(230, 22, 45)', '\f18a'],
  ['QQ', 760, 500, '#51b7ec', '\f1d6'],
  ['Douban', 380, 460, 'rgb(42, 172, 94)', '豆'],
  ['Renren', 950, 500, 'rgb(0, 94, 172)', '\f18b'],
  ['Jirengu', 950, 500, '#1296DB', 'H'],
].freeze
PLUGIN_PREFIX = 'zh_l10n_'.freeze
SITE_SETTING_NAME = 'zh_l10n_enabled'.freeze
ONEBOX_SETTING_NAME = 'zh_l10n_http_onebox_override'.freeze

PROVIDERS.each do |provider|
  auth_provider authenticator: "#{provider[0]}Authenticator".constantize.new,
                frame_width: provider[1],
                frame_height: provider[2],
                background_color: provider[3],
                glyph: provider[4],
                enabled_setting: "#{PLUGIN_PREFIX}enable_#{provider[0].downcase}_logins"
end
Dir[File.expand_path('../lib/onebox_override/*.rb', __FILE__)].each { |f| require f }

after_initialize do
  next unless SiteSetting.zh_l10n_enabled

  Dir[File.expand_path('../lib/onebox/*.rb', __FILE__)].each { |f| require f }

  PROVIDERS.each do |provider|
    provider_name = provider[0].downcase
    enable_setting = "#{PLUGIN_PREFIX}enable_#{provider_name}_logins"
    check = "#{provider_name}_config_check".to_sym

    AdminDashboardData.class_eval do
      define_method(check) do
        if SiteSetting.public_send(enable_setting) && (
            SiteSetting.public_send("#{PLUGIN_PREFIX}#{provider_name}_client_id").blank? ||
            SiteSetting.public_send("#{PLUGIN_PREFIX}#{provider_name}_client_secret").blank?)
          I18n.t("dashboard.#{PLUGIN_PREFIX}#{provider_name}_config_warning")
        end
      end
    end
    AdminDashboardData.add_problem_check check
  end

  DiscourseEvent.on(:site_setting_saved) do |site_setting|
    if site_setting.name == SITE_SETTING_NAME && site_setting.value_changed? && site_setting.value == "f" # false
      PROVIDERS.each { |provider| SiteSetting.public_send("#{PLUGIN_PREFIX}enable_#{provider[0].downcase}_logins=", false) }
    end
  end

  module ::DisableUsernameSuggester
    def to_client_hash
      hash = super

      # only catch when a oauth login and a username is random
      if hash[:auth_provider]
        match = (hash[:username]||'').match(/^\d+$/i)

        if SiteSetting.zh_l10n_disable_random_username_sugeestion && match
          hash[:username] = nil

          if SiteSetting.enable_names? && SiteSetting.zh_l10n_disable_random_username_sugeestion && match
            hash[:name] = nil
          end
        end
      end

      hash
    end
  end

  Auth::Result.class_eval do
    prepend ::DisableUsernameSuggester
  end
end
