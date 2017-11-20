
rule m2318_63b14084dae30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.63b14084dae30912"
     cluster="m2318.63b14084dae30912"
     cluster_size="60"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03e287f71d480c51f48ae8a67823da62','0bb772726d4ae8a94c1f443e693404d4','70bb13c4e423a3ff48190fe4d858c903']"

   strings:
      $hex_string = { 6a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
