
rule k2319_181514b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181514b9caa00b12"
     cluster="k2319.181514b9caa00b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c3821f8a7f2fcfdddec483b8a801b699e9937ab0','bbb58fb4eed5d88dadd6a8abe1f28a5954fb37cf','3f036baa2770ba65994f736e75d5387731d90d22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181514b9caa00b12"

   strings:
      $hex_string = { 3f3134353a2830783133382c36382e324531292929627265616b7d3b666f72287661722059355020696e2056305a3550297b6966285935502e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
