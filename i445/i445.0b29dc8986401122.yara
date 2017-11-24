
rule i445_0b29dc8986401122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b29dc8986401122"
     cluster="i445.0b29dc8986401122"
     cluster_size="6"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="darkbot dorkbot winlnk"
     md5_hashes="['0dee2104147d0ea4b2bd25ff90fe0495','0fb3cfb88fec03c006ed5e20a04e664c','c02959720b2196e87f67351d6a08589e']"

   strings:
      $hex_string = { 000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
