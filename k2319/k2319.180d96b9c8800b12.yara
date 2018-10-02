
rule k2319_180d96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180d96b9c8800b12"
     cluster="k2319.180d96b9c8800b12"
     cluster_size="35"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['90a455e49e884adb7b2802c1eb90da0f6da6cc0d','d52f62f38f0ac608c47a897f5b12805eb0df03c9','9ecd995e32eb29c48133b96e9efaee4b60e7e7ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180d96b9c8800b12"

   strings:
      $hex_string = { 2e353945323f28312e30373645332c313139293a2832312c3930292929627265616b7d3b7661722073325a31593d7b27493559273a66756e6374696f6e284a2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
