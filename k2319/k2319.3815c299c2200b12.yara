
rule k2319_3815c299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3815c299c2200b12"
     cluster="k2319.3815c299c2200b12"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['05d4152a45ec492cddb3e9595085d6651ea9c76e','85bcc2d73096228b880b9dbdd4e050261c4c848b','274ba8bd05e3472582ba95931b32efa7eb6935e5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3815c299c2200b12"

   strings:
      $hex_string = { 2830783233362c37392e38304531292929627265616b7d3b76617220693456334d3d7b2769327a273a226368222c2773324d273a66756e6374696f6e28422c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
