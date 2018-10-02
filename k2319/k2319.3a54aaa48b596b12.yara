
rule k2319_3a54aaa48b596b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54aaa48b596b12"
     cluster="k2319.3a54aaa48b596b12"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['6189c8f135811c06f3587b736255525dd8ed7290','b0a59254dc80950241a736fee27dfd92fc94c51c','d92ae2dc9fc299411af3c6bbc6e4f28cf96d57e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54aaa48b596b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
