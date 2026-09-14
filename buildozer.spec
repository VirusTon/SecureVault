[app]

title = Secure Vault
package.name = securevault
package.domain = org.vault

source.dir = .
source.include_exts = py,png,jpg,jpeg,kv,atlas,json,xml

version = 1.0.0

requirements = python3,kivy==2.3.0,cryptography,pyjnius,plyer

orientation = portrait
fullscreen = 0

android.api = 36
android.minapi = 24
android.ndk = 28c

android.archs = arm64-v8a,armeabi-v7a

android.allow_backup = True
android.enable_androidx = True

android.add_resources = %(source.dir)s/res
android.extra_manifest_xml = %(source.dir)s/android_manifest.xml


[buildozer]

log_level = 2
warn_on_root = 1
