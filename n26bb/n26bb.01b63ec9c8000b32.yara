
rule n26bb_01b63ec9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.01b63ec9c8000b32"
     cluster="n26bb.01b63ec9c8000b32"
     cluster_size="1144"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom hpgen"
     md5_hashes="['449faf73befa695bc799b853e6c0e28ef3bf6703','325bdee35dce9c9e6f1685cc8d95c373fc9bdd4c','cba87208cc82ad295a66a60f0b6973f8b8f62486']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.01b63ec9c8000b32"

   strings:
      $hex_string = { 8d46185750e84d0dffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
