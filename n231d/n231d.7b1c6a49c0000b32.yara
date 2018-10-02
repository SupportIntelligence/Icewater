
rule n231d_7b1c6a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.7b1c6a49c0000b32"
     cluster="n231d.7b1c6a49c0000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp androidos riskware"
     md5_hashes="['639d9334a4e2cd52fd768a17370275cc27518405','ce9cd510274d5b44ae565a78004207d21487330b','28160673343daf9256cf2a4c48b772f99ccf4a28']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.7b1c6a49c0000b32"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
