
rule nfc8_3134b4c726916b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.3134b4c726916b36"
     cluster="nfc8.3134b4c726916b36"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="podec fobus androidos"
     md5_hashes="['7e1975d7d99a11e3ea6640b3a82bc0b472eb02cf','058bb357ddc1edea2304176917d30960977cf644','03ad6bc6dcf1fb5d3f6f442593a333e89f755ef6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.3134b4c726916b36"

   strings:
      $hex_string = { 27eb5c570ad9e6d1178f9d239efe0cfc0c4fde7d0bb175a88e3936cee14941ff4811e905ab3cada906761c3e5d3d67bec3ae9172d7748b303214f21eafb9611b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
