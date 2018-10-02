
rule n231d_3b1e6949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b1e6949c0000b32"
     cluster="n231d.3b1e6949c0000b32"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['f6b63f6d5406d27ed3c276290d9554a0991a918c','9b726dae7a4507578029456ee50825120589482a','1c4aa75480ffb925ec5f48549c10b2e1c290ae03']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b1e6949c0000b32"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
