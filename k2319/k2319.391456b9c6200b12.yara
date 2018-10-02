
rule k2319_391456b9c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391456b9c6200b12"
     cluster="k2319.391456b9c6200b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a9eb2369d1afb9ce455b5d49d619635cd3b53bc4','c3fd133ea11c832e4b88331ea8b69d1adcfbeb3a','45b158376bc7913272b3cbeecc8cd68cbc0c27ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391456b9c6200b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20475b6f5d3b7d76617220433d2828307846442c392e37324532293e2830783137392c39352e36304531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
