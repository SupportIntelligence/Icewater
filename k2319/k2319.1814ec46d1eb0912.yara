
rule k2319_1814ec46d1eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1814ec46d1eb0912"
     cluster="k2319.1814ec46d1eb0912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik fevide"
     md5_hashes="['532dcebcebcbc0e4bb4051b175dec2749569b693','feccaa80b4a09f989384d62aa4dc7aa7cc6fcef2','beb36b8bc4f15b37fbcdfbd052dd4bdc5202b442']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1814ec46d1eb0912"

   strings:
      $hex_string = { 3a28322e393845322c3078323141292929627265616b7d3b76617220663351323d7b27623464273a22697374656e222c27533246273a22436f6465222c274236 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
