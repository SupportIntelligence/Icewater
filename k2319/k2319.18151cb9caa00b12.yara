
rule k2319_18151cb9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18151cb9caa00b12"
     cluster="k2319.18151cb9caa00b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b54b7554229668d685f4a980a196ec888e131fdb','abd10461da58363026e0d8ac937cdb6c00b2dc46','4d2d6d6dd9ce2742d07c7bd241fffb12a0d73658']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18151cb9caa00b12"

   strings:
      $hex_string = { 3f3134353a2830783133382c36382e324531292929627265616b7d3b666f72287661722059355020696e2056305a3550297b6966285935502e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
