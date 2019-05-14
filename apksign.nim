
import zip/zipfiles
import streams
import std/sha1
import base64
import strutils
import tables
import os


type
  Signer = object
    manifest: string
    signatureFile: string
    manifestHash: string
    entryHash: Table[string, string]


proc base64sha1(s: string): string =
  result = base64.encode(parseHexStr($s.secureHash))

proc skipFile(s: string): bool =
  if s.len > 8 and s[0..7] == "META-INF":
    var (dir, name, ext) = s.splitFile
    return ext in [ ".MF", ".SF", ".RSA", ".DSA", ".EC" ]

proc joinCrLf(ss: openarray[string]): string = ss.join("\r\n") & "\r\n"


proc buildManifest(signer: var Signer, src: var ZipArchive) =

  ## Build MANIFEST.MF

  signer.manifest.add joinCrLf([
     "Manifest-Version: 1.0",
     "Built-By: Generated-by-ADT",
     "Created-By: Android Gradle 3.3.2",
     ""
  ])

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      let entry = joinCrLf([
        "Name: " & f,
        "SHA1-Digest: " & s.readAll().base64sha1,
        ""
      ])
      signer.manifest.add entry
      signer.entryHash[f] = base64sha1(entry)
      s.close()

  signer.manifestHash = base64sha1(signer.manifest)


proc buildSignatureFile(signer: var Signer, src: var ZipArchive) =

  ## Build CERT.CF

  signer.signatureFile.add joinCrLf [
    "Signature-Version: 1.0",
    "Created-By: 1.0 (Android)",
    "SHA1-Digest-Manifest: " & signer.manifestHash,
    "X-Android-APK-Signed: 2",
    ""
  ]
  
  for f in src.walkFiles:
    if not f.skipFile:
      signer.signatureFile.add joinCrLf [
        "Name: " & f,
        "SHA1-Digest: " & signer.entryHash[f],
        ""
      ]


proc buildSignedApk(signer: var Signer, src: var ZipArchive) =
  
  var dst: ZipArchive
  doAssert dst.open("demo-signed.apk", fmWrite)

  dst.addFile("META-INF/MANIFEST.MF", newStringStream(signer.manifest))
  dst.addFile("META-INF/CERT.SF", newStringStream(signer.signatureFile))

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      echo "adding ", f
      dst.addFile(f, s)

  dst.close()


var signer = Signer(entryHash: initTable[string, string]())


var src: ZipArchive
doAssert src.open("demo.apk", fmRead)

signer.buildManifest(src)
signer.buildSignatureFile(src)

signer.buildSignedAPK(src)



#let manifestHash = base64sha1(manifest)
#let certSf = mkSignatureFile(src, manifestHash)
#echo certSf
