
rule p3f0_239896c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f0.239896c9cc000b12"
     cluster="p3f0.239896c9cc000b12"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi mediamagnet gamemodding"
     md5_hashes="['1706d9fc6c5bbd148513c0692cd56511','23ebd897ff984185cf98bf7797918625','dad28b0297db028acf5979dbf722ba5b']"

   strings:
      $hex_string = { 2b06bb8586df8177fd0b0da6f7c54e765d92437a409d14e4f258f6e1caa3d6892773fa22a7b35bc8667838c3b59915dca4d351b26afb2c1505013bdb1609bf64 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
