# Uncomment the next line to define a global platform for your project
platform :ios, '17.0'

target 'DataGateIOS' do
  # Comment the next line if you don't want to use dynamic frameworks
  use_frameworks!

  # Pods for DataGateIOS
  pod 'GoogleSignIn'
end

target 'DataGateVPNExtension' do
  # Comment the next line if you don't want to use dynamic frameworks
  use_frameworks!

  # Pods for DataGateVPNExtension
  # NOTE: mbedTLS pod removed - using static libraries instead (libmbedtls.a, libmbedcrypto.a, libmbedx509.a)
  # pod 'mbedTLS', '~> 2.28'
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '17.0'
      config.build_settings['CLANG_CXX_LANGUAGE_STANDARD'] = 'gnu++20'
    end
  end
end
