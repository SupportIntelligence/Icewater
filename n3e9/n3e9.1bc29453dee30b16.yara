
rule n3e9_1bc29453dee30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc29453dee30b16"
     cluster="n3e9.1bc29453dee30b16"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious genmalicious"
     md5_hashes="['1f5aa8e1a6a7949adf8090dbf41c7bd4','278425815dd07af110103b5fa2ff5ec4','c25f7adf76908076b0b4746aabcdc2b2']"

   strings:
      $hex_string = { 004c00650066007400020055007000050052006900670068007400040044006f0077006e0000004000470072006f007500700049006e00640065007800200063 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
