
rule k2319_29159cb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29159cb9c8800b32"
     cluster="k2319.29159cb9c8800b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4766beeb48218eb5062a506643a76b353c1d1ced','404cad760bbb49ebd283a085c828a270e9cf1565','3e17c99e7049223699a617bc350200353fa51561']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29159cb9c8800b32"

   strings:
      $hex_string = { 313139293a28332e2c32372e292929627265616b7d3b7661722052347639353d7b27413735273a66756e6374696f6e28582c4c297b72657475726e2058213d4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
