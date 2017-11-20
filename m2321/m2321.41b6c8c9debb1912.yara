
rule m2321_41b6c8c9debb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.41b6c8c9debb1912"
     cluster="m2321.41b6c8c9debb1912"
     cluster_size="5"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cripack vawtrak"
     md5_hashes="['052f39631fde67c770ad951499027a4a','3cb1ccf3dbf37c07d54e30b2b91ada16','d09e8a0b7dc1db75e9571cae854401f9']"

   strings:
      $hex_string = { 685ad42ecf6c3f94b218ba9c0f7739456e95088373df3daab6358810c685c2a3eaee7c8f27d33b0be9ac1ba699c1eb0efd96d958f7f1298437f5cd6d03e425fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
