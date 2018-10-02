
rule k2319_291d14b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291d14b9c8800b32"
     cluster="k2319.291d14b9c8800b32"
     cluster_size="145"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['65044e5a7aaf3f3b98327b49e9de2f471d9b9aa3','d10a3f78a5444192036e7c0a71797245095a1c48','396df27ceb2dbc948bcff33c894af51812c514c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291d14b9c8800b32"

   strings:
      $hex_string = { 34312e292929627265616b7d3b766172206a386338493d7b276c3644273a226765222c27703849273a66756e6374696f6e284c2c71297b72657475726e204c3c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
