
import zip/zipfiles
import streams
import std/sha1
import base64
import strutils
import tables
import os, osproc


const
  apkIn = "demo.apk"
  apkOut = "demo-signed.apk"
  signKey = "test.key.pem"
  signCert = "test.cert.pem"
  tmpFile = "tmp"

type
  Signer = object
    manifest: string
    certSf: string
    certRsa: string
    manifestHash: string
    entryHash: Table[string, string]


proc base64sha1(s: string): string =
  result = base64.encode(parseHexStr($s.secureHash))

proc skipFile(s: string): bool =
  let (dir, name, ext) = s.splitFile
  return dir == "META-INF" and ext in [ ".MF", ".SF", ".RSA", ".DSA", ".EC" ]

proc joinCrLf(ss: openarray[string]): string =
  ss.join("\r\n") & "\r\n\r\n"


proc buildManifestSf(signer: var Signer, src: var ZipArchive) =

  echo "- Building MANIFEST.SF"

  signer.manifest.add joinCrLf([
     "Manifest-Version: 1.0",
     "Built-By: Generated-by-ADT",
     "Created-By: Android Gradle 3.3.2",
  ])

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      let entry = joinCrLf([
        "Name: " & f,
        "SHA1-Digest: " & s.readAll().base64sha1,
      ])
      signer.manifest.add entry
      signer.entryHash[f] = base64sha1(entry)
      s.close()

  signer.manifestHash = base64sha1(signer.manifest)


proc buildCertSf(signer: var Signer, src: var ZipArchive) =

  echo "- Building CERT.SF"

  signer.certSf.add joinCrLf [
    "Signature-Version: 1.0",
    "Created-By: 1.0 (Android)",
    "SHA1-Digest-Manifest: " & signer.manifestHash,
  ]
  
  for f in src.walkFiles:
    if not f.skipFile:
      signer.certSf.add joinCrLf [
        "Name: " & f,
        "SHA1-Digest: " & signer.entryHash[f],
      ]


proc buildCertRsa(signer: var Signer) =

  echo "- Building CERT.RSA"

  writeFile(tmpFile & ".in", signer.certSf)
  let cmd = "openssl smime" &
               " -sign -inkey " & signKey & 
               " -signer " & signCert & 
               " -binary -outform DER" &
               " -noattr" &
               " -in " & tmpFile & ".in" &
               " -out " & tmpFile & ".out" 

  let (stdout, rv) = execCmdEx(cmd)
  doAssert rv == 0
  signer.certRsa = readFile(tmpFile & ".out")
  removeFile(tmpFile & ".in")
  removeFile(tmpFile & ".out")


proc buildSignedApk(signer: var Signer, src: var ZipArchive) =

  echo "- Building signed APK"
  
  var dst: ZipArchive
  doAssert dst.open(apkOut, fmWrite)

  dst.addFile("META-INF/MANIFEST.MF", newStringStream(signer.manifest))
  dst.addFile("META-INF/CERT.SF", newStringStream(signer.certSf))
  dst.addFile("META-INF/CERT.RSA", newStringStream(signer.certRsa))

  for f in src.walkFiles:
    if not f.skipFile:
      let s = src.getStream(f)
      dst.addFile(f, s)

  dst.close()




var src: ZipArchive
doAssert src.open(apkIn, fmRead)

var signer = Signer(entryHash: initTable[string, string]())

signer.buildManifestSf(src)
signer.buildCertSf(src)
signer.buildCertRsa()

signer.buildSignedAPK(src)

writeFile("flop", signer.certRsa)


#let manifestHash = base64sha1(manifest)
#let certSf = mkCertSf(src, manifestHash)
#echo certSf
