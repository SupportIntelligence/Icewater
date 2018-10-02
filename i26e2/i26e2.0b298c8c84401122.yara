
rule i26e2_0b298c8c84401122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.0b298c8c84401122"
     cluster="i26e2.0b298c8c84401122"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk darkbot"
     md5_hashes="['0b3cc06cdcb7e4c9cd3cf963adc160e229c9f1b8','ca84f31a775b9326afd2412d2dc504af968e8feb','4f61fc59b0157abae03ab5c19df6c684bb461991']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.0b298c8c84401122"

   strings:
      $hex_string = { 000000000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
