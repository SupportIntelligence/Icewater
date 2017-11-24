
rule m2318_6939a808d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6939a808d9bb0912"
     cluster="m2318.6939a808d9bb0912"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['04bb6a648916378b595f5274d973cc52','0a8bfc67e711469c666dec358bf2c890','fe42711214191c9ea52c9c9d7dec139e']"

   strings:
      $hex_string = { 2043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e6420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
