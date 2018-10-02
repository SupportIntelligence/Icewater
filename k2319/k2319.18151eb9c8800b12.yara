
rule k2319_18151eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18151eb9c8800b12"
     cluster="k2319.18151eb9c8800b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5b3c8c6a5e269b09574f44c47f78a119cf8b60ab','143e850711ca4d074bb3f631abc4bc74da880897','597fa5306ac44463e751dd404ae54eb217ad9068']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18151eb9c8800b12"

   strings:
      $hex_string = { 3f3134353a2830783133382c36382e324531292929627265616b7d3b666f72287661722059355020696e2056305a3550297b6966285935502e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
