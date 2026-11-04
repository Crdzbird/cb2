#
# cb2_flutter for iOS: the prebuilt C ABI of cb2 as an XCFramework. Nothing
# is compiled here; build libcb2_c.xcframework from a static libcb2_c with
# libsodium, BLAKE3, liboqs and libcrypto merged in (see README.md) and
# place it at ios/Frameworks/libcb2_c.xcframework before `pod install`.
#
Pod::Spec.new do |s|
  s.name             = 'cb2_flutter'
  s.version          = '0.1.0'
  s.summary          = 'The cb2 token library for Flutter.'
  s.description      = <<-DESC
The C ABI of cb2, the post-quantum token library, packaged for Flutter.
                       DESC
  s.homepage         = 'https://github.com/crdzbird/cb2'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'cb2' => 'cb2@users.noreply.github.com' }

  s.source           = { :path => '.' }
  s.vendored_frameworks = 'Frameworks/libcb2_c.xcframework'
  s.libraries = 'c++'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # A static library xcframework contributes nothing to the app unless the
  # linker is told to keep it, since no Swift or Objective-C code refers
  # to the cb2_* symbols; Dart finds them through DynamicLibrary.process().
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) -force_load "$(PODS_XCFRAMEWORKS_BUILD_DIR)/cb2_flutter/libcb2_c.a"'
  }
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
