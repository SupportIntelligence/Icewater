
rule o2319_39a4f2c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.39a4f2c9c8000b32"
     cluster="o2319.39a4f2c9c8000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer coinhive"
     md5_hashes="['83f71e5db1a52333a02d5b15302b6abb25da4cd8','829b112e9635caf39a1a8e4863da1aac6c0279a3','e603ec25ad4950ac072ce77a260a797de04d0332']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.39a4f2c9c8000b32"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20582e4348494c442e746573 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
