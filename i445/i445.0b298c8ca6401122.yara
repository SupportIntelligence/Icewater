
rule i445_0b298c8ca6401122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b298c8ca6401122"
     cluster="i445.0b298c8ca6401122"
     cluster_size="11"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="darkbot dorkbot winlnk"
     md5_hashes="['146c740f4c69d0d143139e84d047e2a1','1f238c577670dbce20d84c1869aac21f','d7e1db5d2e5e1a002c9a44e0936aff50']"

   strings:
      $hex_string = { 000000000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
