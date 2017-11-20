
rule m2318_613cea88d8bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.613cea88d8bb0912"
     cluster="m2318.613cea88d8bb0912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3a418053ba7f155f199be2ecf7fdaa60','5de1859942c55dd4f171b2c1435dd16e','f3c96481a11e3fc67cedcb7d256f30b3']"

   strings:
      $hex_string = { 74652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
