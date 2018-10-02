
rule k2319_1a189eb9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a189eb9c8800912"
     cluster="k2319.1a189eb9c8800912"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6ea42af082b202ce9b5a4a36bec1950003ab18da','bbc3439abcd43edbc22fac47a8dae6940b644de9','9230df6e02f8c811637cbffd6fbb86295ac175e3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a189eb9c8800912"

   strings:
      $hex_string = { 3a283131342e2c30784132292929627265616b7d3b766172206f3943333d7b27733142273a66756e6374696f6e28442c46297b72657475726e20443c463b7d2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
