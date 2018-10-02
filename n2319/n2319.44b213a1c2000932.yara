
rule n2319_44b213a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.44b213a1c2000932"
     cluster="n2319.44b213a1c2000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="valyria exploit script"
     md5_hashes="['273a2787691caaaf6d9085047d4016fcd2972b25','cba55fd3048430ba9fca223bdebf8b5e5c3d4592','27385b494f3bd3520cd6f3c1efd40799c2708714']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.44b213a1c2000932"

   strings:
      $hex_string = { 626a7731343733300d0a5c6f626a68323839350d0a7b5c2a5c6f626a636c61737320457863656c2e0d0a53686565742e0d0a387d7b5c2a5c6f626a6461746120 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
