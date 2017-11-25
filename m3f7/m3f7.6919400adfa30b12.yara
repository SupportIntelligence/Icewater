
rule m3f7_6919400adfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6919400adfa30b12"
     cluster="m3f7.6919400adfa30b12"
     cluster_size="104"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01afe041b677dee9c4d9e8d09ba02458','01dd335b7b8493ee5f1584257faa6da4','20e0f5cdd95a8d9f04b9d694411743d8']"

   strings:
      $hex_string = { 2043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e6420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
