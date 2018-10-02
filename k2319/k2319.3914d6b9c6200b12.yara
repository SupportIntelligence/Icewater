
rule k2319_3914d6b9c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3914d6b9c6200b12"
     cluster="k2319.3914d6b9c6200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e3bb6962c9d65261c9d4f167f4f8a888afc18100','ba705409640cd7d0ae8454b90ca4b550a5efb112','bf24995faf4ba7a778b50cb0cb9e4f977a5924b5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3914d6b9c6200b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20475b6f5d3b7d76617220433d2828307846442c392e37324532293e2830783137392c39352e36304531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
