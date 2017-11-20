
rule m2321_4b9a7294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b9a7294d6830912"
     cluster="m2321.4b9a7294d6830912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['56bbf5b017e0270053c6f9c9e656f22a','723b5a24a90adb09e84118c3599aff41','ee45a6e0be65c850e109dae4a057e302']"

   strings:
      $hex_string = { 9cc0ff97a2b05d4c6fab6e54bbf119cc53cef4bd5647d7e658c7c98aa928ea7d50f7d538b159e3aeeb181752afc15104261dcd49dae772569e0a39a1e9842420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
