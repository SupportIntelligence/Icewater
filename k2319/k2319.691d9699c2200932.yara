
rule k2319_691d9699c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691d9699c2200932"
     cluster="k2319.691d9699c2200932"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5b1e97a7c24b215ab266a7e28232676eff85ec28','7ad7472fb81b820ff9463f9d351ed3acbddf981e','6041b37a7192b8e42bb21af2d5b98111e928e3a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691d9699c2200932"

   strings:
      $hex_string = { 783144302c31302e39394532292929627265616b7d3b766172205a366d326a3d7b2778376a273a66756e6374696f6e284e2c55297b72657475726e204e7c553b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
