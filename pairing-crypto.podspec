
Pod::Spec.new do |s|
  s.name         = "pairing-crypto"
  s.version      = "0.1.0"
  s.summary      = "Pairing Crypto Library"
  s.homepage     = "https://github.com/mattrglobal/pairing_crypto"
  s.license      = "Apache-2.0"
  s.authors      = "MATTR Team"

  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/mattrglobal/pairing_crypto.git", :tag => "#{s.version}" }

  s.vendored_libraries = 'wrappers/obj-c/libraries/libpairing_crypto.a'
  s.libraries = 'bbs'
  s.source_files = 'wrappers/obj-c/pairing_crypto/*/*.{h,m,mm}'
  s.requires_arc = true

  s.pod_target_xcconfig = {
    'VALID_ARCHS' => 'arm64 x86_64',
    "HEADER_SEARCH_PATHS" => "$(CONFIGURATION_BUILD_DIR)",
    "ENABLE_BITCODE" => "YES"
  }

  s.user_target_xcconfig = { 'VALID_ARCHS' => 'arm64 x86_64' }

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'wrappers/obj-c/tests/*.{h,m}'
  end
end