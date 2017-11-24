
rule m2377_631b2008d9ab0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.631b2008d9ab0932"
     cluster="m2377.631b2008d9ab0932"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2556543cfc030d2a9f4f22fa27f5053b','a2127231480a702591b63a62c79ca95e','fbc2c312c6eb4ee956f3f006c46a7cfd']"

   strings:
      $hex_string = { 652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
