
rule m3f7_63b10084da630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63b10084da630912"
     cluster="m3f7.63b10084da630912"
     cluster_size="41192"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00002a482721b9e64830719a53b6c445','0000b77028ff3e7889582312ea2ab0ee','0015da11081d7573b7b43c33f1f3d705']"

   strings:
      $hex_string = { 626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
