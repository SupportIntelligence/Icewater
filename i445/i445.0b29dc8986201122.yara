
rule i445_0b29dc8986201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b29dc8986201122"
     cluster="i445.0b29dc8986201122"
     cluster_size="6"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot darkbot winlnk"
     md5_hashes="['0de238e96c436846bc11f1bb0a2dbb2d','1d0fa070209a0af79d8f5339493f0f80','e66ffb0d284a3532f957d44dc71a2be8']"

   strings:
      $hex_string = { 002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065000000000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
