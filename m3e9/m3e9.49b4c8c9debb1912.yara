
rule m3e9_49b4c8c9debb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49b4c8c9debb1912"
     cluster="m3e9.49b4c8c9debb1912"
     cluster_size="29"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cripack vawtrak"
     md5_hashes="['140abf9fe910d24cb8593aeff30200bc','251e61523966c47b7c29ac5d57d52704','b62ec8c126c0aaec599cec729f27221e']"

   strings:
      $hex_string = { 685ad42ecf6c3f94b218ba9c0f7739456e95088373df3daab6358810c685c2a3eaee7c8f27d33b0be9ac1ba699c1eb0efd96d958f7f1298437f5cd6d03e425fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
