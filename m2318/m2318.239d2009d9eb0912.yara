
rule m2318_239d2009d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.239d2009d9eb0912"
     cluster="m2318.239d2009d9eb0912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['17e296dab12bff080d134f9bea0aa7a9','4be22a4c84aa9fe1ffec45d880cf81c9','e97348d997a3f69ab39f5faca2ecc341']"

   strings:
      $hex_string = { 6a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
