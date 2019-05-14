
import zip/zipfiles
import streams
import std/sha1
import base64
import strutils


const skipFiles = [
  "META-INF/CERT.RSA",
  "META-INF/CERT.SF",
  "META-INF/MANIFEST.MF",
]

proc sha1base64(s: string): string =
  result = base64.encode(parseHexStr($s.secureHash))


proc skipFile(s: string): bool =
  if s in skipFiles:
    return true
  
proc mkManifest(src: var ZipArchive): string =

  var o: seq[string]

  o.add "Manifest-Version: 1.0"
  o.add "Built-By: Generated-by-ADT"
  o.add "Created-By: Android Gradle 3.3.2"
  o.add ""

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      o.add "Name: " & f
      o.add "SHA1-Digest: " & s.readAll().sha1base64
      o.add ""
      s.close()

  o.add ""
  result = o.join("\r\n")


var src: ZipArchive
doAssert src.open("demo.apk", fmRead)

let manifest = mkManifest(src)
let manifestHash = sha1base64(manifest)
echo manifest
echo manifestHash
