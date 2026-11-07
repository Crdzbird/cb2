#
# cb2_flutter for macOS: the C ABI of cb2 as the dynamic framework
# cb2_c.framework, vendored from cb2_flutter/Frameworks/cb2_c.xcframework,
# which tool/build_xcframework.sh builds and cb2_flutter/Package.swift
# also serves to Swift Package Manager. Package cb2 opens it by name.
#
Pod::Spec.new do |s|
  s.name             = 'cb2_flutter'
  s.version          = '0.2.0'
  s.summary          = 'The cb2 token library for Flutter.'
  s.description      = <<-DESC
The C ABI of cb2, the post-quantum token library, packaged for Flutter.
                       DESC
  s.homepage         = 'https://github.com/Crdzbird/cb2'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Crdzbird' => 'https://github.com/Crdzbird' }

  s.source           = { :path => '.' }
  s.vendored_frameworks = 'cb2_flutter/Frameworks/cb2_c.xcframework'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '11.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
