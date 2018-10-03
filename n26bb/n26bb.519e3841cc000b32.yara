
rule n26bb_519e3841cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.519e3841cc000b32"
     cluster="n26bb.519e3841cc000b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aklujlli patched"
     md5_hashes="['9b90aa26fa8a5095ebac1cb5f448e1a4b97358f1','27d5dc11b188607934abf72efbcfcfdab85b3ea6','ee26ea5e477f67b3cdf6be485acbd05746845d59']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.519e3841cc000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
