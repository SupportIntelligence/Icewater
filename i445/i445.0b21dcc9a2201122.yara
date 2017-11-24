
rule i445_0b21dcc9a2201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b21dcc9a2201122"
     cluster="i445.0b21dcc9a2201122"
     cluster_size="5"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot darkbot winlnk"
     md5_hashes="['75270f01a7d8bff18efd90a9a08be191','863518774f0eb5fb1c3c39e3ed4cd20f','eadfed8b38599509496a969405903983']"

   strings:
      $hex_string = { 000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
