
rule n26bb_611d62e9c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.611d62e9c0800b32"
     cluster="n26bb.611d62e9c0800b32"
     cluster_size="76"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ilivid bandoo searchsuite"
     md5_hashes="['f725c6d4c2d74ba893a362f3f929cdf15b84358a','9c0e79ea756a6bfc7440c7a42817114da934170b','78f6e5b0491f0e97039aab53b70f039a4cc15849']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.611d62e9c0800b32"

   strings:
      $hex_string = { ff495c9bff475c9aff445796ff3f5491ff3b518dff324885ff2e4481ff29376ffb093577f60267c0fd0369c4ff0365beff67a5d9ff72abdbff418ed0ff1e75c6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
