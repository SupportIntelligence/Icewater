
rule m2320_56c97ec1c8000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.56c97ec1c8000112"
     cluster="m2320.56c97ec1c8000112"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro lookslike malicious"
     md5_hashes="['58e187dd16a8a204ea1926c3dffbece84de5be34','f38a0e714b169804ecc803e6b9b2cb05e4a2fa20','f2362794f961ea95e13e417d28099e158a02f182']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.56c97ec1c8000112"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
