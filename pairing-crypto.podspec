Pod::Spec.new do |s|
  s.name         = "pairing-crypto"
  s.version      = "0.1.0"
  s.summary      = "Pairing Crypto Library"
  s.homepage     = "https://github.com/mattrglobal/pairing_crypto"
  s.license      = "Apache-2.0"
  s.authors      = "MATTR Team"

  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => "https://github.com/mattrglobal/pairing_crypto.git", :tag => "#{s.version}" }

  # TODO: The external libraries must be commited to the repo when we decided to publish this pod.
  s.vendored_frameworks = 'libpairing_crypto_c.xcframework'
  s.source_files = 'wrappers/obj-c/pairing_crypto/*.{h,m,mm}', 'libpairing_crypto_c.xcframework'

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'wrappers/obj-c/tests/**/*.{h,m}'
  end
end
