
rule m2318_5c9b008cc2210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.5c9b008cc2210912"
     cluster="m2318.5c9b008cc2210912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['4c280bc1e8c28763b95af7a3b20dda03','6ac7f58dd5f6238904b9948af62a213a','db76a0f96d086300b5d8d808aa06e0f0']"

   strings:
      $hex_string = { 626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
