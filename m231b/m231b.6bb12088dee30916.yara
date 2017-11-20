
rule m231b_6bb12088dee30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.6bb12088dee30916"
     cluster="m231b.6bb12088dee30916"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['25d0b09d49f373959cb5413d5e81a34b','5da316f72fdbdd0c58c7520c9798647b','d89d64ea5d5a944b76c5b5c52d91de5d']"

   strings:
      $hex_string = { 434c6e6728222648222026204d6964285772697465446174612c692c322929290d0d0a4e6578740d0d0a46696c654f626a2e436c6f73650d0d0a456e64204966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
