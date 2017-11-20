
rule m2318_61b90017ded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61b90017ded30912"
     cluster="m2318.61b90017ded30912"
     cluster_size="901"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00281b5fa1b9f1456ad222b189c92bb0','00ab8f898334f9666416179ac654a6fd','060638b6844a49033c14e1225e29e2b5']"

   strings:
      $hex_string = { 687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64204966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
