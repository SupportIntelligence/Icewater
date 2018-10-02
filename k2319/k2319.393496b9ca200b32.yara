
rule k2319_393496b9ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393496b9ca200b32"
     cluster="k2319.393496b9ca200b32"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0adbbcd6189a6f06dd5bddefdcbfc279a9632ac1','7dc78e781cef272c7c80d2547536301029f3bf9e','5a6048c0aa02e90d317deb909f16d93f83ac4f55']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393496b9ca200b32"

   strings:
      $hex_string = { 3134392e292929627265616b7d3b7661722045384136303d7b27753156273a2252222c27683456273a22797a222c27653530273a66756e6374696f6e28512c46 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
