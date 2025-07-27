Pod::Spec.new do |s|
  s.name           = 'QuantumCryptoModule'
  s.version        = '1.0.0'
  s.summary        = 'Quantum-resistant cryptography module for Expo'
  s.description    = 'A native module providing NIST post-quantum cryptography algorithms including Kyber and Dilithium'
  s.author         = { 'Your Name' => 'your.email@example.com' }
  s.homepage       = 'https://github.com/gideon-amp/e2e-poc'
  s.platforms      = { :ios => '13.0' }
  s.source         = { :git => 'https://github.com/gideon-amp/e2e-poc.git' }
  s.static_framework = true
  s.dependency 'ExpoModulesCore'

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
  s.exclude_files = "**/node_modules/**/*"

  s.vendored_frameworks = 'liboqs.xcframework'

  s.compiler_flags = '-DOQS_ENABLE_KEM_KYBER', '-DOQS_ENABLE_SIG_DILITHIUM'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule',
    'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES'
  }

  s.swift_version = '5.0'
end