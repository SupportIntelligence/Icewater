
rule k2319_39129ae9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39129ae9c8800b12"
     cluster="k2319.39129ae9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ec42ac4edce255c0b5194bf018c0074d268c2388','b70951e4ac48b2b0643e1709504a314399eee2a6','beffbaf200190b903c2159a09dd8096d8dcb9437']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39129ae9c8800b12"

   strings:
      $hex_string = { 3d756e646566696e6564297b72657475726e20445b655d3b7d76617220503d282830783141442c342e36324532293e2830783131312c38322e293f2833352e37 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
