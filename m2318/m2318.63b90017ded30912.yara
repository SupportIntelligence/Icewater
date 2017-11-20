
rule m2318_63b90017ded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.63b90017ded30912"
     cluster="m2318.63b90017ded30912"
     cluster_size="396"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0026b47685b90586f1539a7be8d08ef8','0072d078ab31072c255d2450ba1dba5e','0b45e32ef2880280d894bc54cfb7c295']"

   strings:
      $hex_string = { 626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
