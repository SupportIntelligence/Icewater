
rule nfc8_21b45694d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.21b45694d9eb0912"
     cluster="nfc8.21b45694d9eb0912"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="podec fobus mkero"
     md5_hashes="['ab2c33eaa5396d5448ce1ac6cd5668a1837f0a61','c6867d6a65fd75ae6e88d76a756b6b5403d89748','a3fb56f1bc62f2eff851e31b03d39bfc6f5e3a24']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.21b45694d9eb0912"

   strings:
      $hex_string = { 27eb5c570ad9e6d1178f9d239efe0cfc0c4fde7d0bb175a88e3936cee14941ff4811e905ab3cada906761c3e5d3d67bec3ae9172d7748b303214f21eafb9611b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
