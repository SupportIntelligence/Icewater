
rule k2319_1e16e84ccaab9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e16e84ccaab9912"
     cluster="k2319.1e16e84ccaab9912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script browext browser"
     md5_hashes="['2d2ec1bcceb990b9eaea32981a3b61809109f84f','87f77dc9c21edf15e22de3ec7b61aadbf927ca49','6823f91d118dc112d6d8b7eee41ed68b37be8df3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e16e84ccaab9912"

   strings:
      $hex_string = { 3146432c3078314437292929627265616b7d3b766172205834583d7b276a334a273a227572222c27723648273a277572272c276c38273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
