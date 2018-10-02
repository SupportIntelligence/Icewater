
rule k2318_5290794bc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5290794bc2220b12"
     cluster="k2318.5290794bc2220b12"
     cluster_size="1571"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['5ce0eb7e0277eeb79e2790420b2d0e45702f5b6e','589d9cfdb0aff49fecc7818d49c26efc83397c64','f4a924bf8b22263bf0fb85e78d1e4a27e296939d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5290794bc2220b12"

   strings:
      $hex_string = { 683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
