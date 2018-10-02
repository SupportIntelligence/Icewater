
rule n26bb_148bbec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.148bbec9c4000b12"
     cluster="n26bb.148bbec9c4000b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ibryte installer optimum"
     md5_hashes="['6db56fd231cb94b599978bf4c405a99c248a100f','79b0335ddffbd7c310a338b4651836bf0a0f45d7','02286bf1de26229688843f53ec78c0e8abbb8e5b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.148bbec9c4000b12"

   strings:
      $hex_string = { ebbe395d0c75b6536a04bfa062440057ff7514ff751050e86615010083c41885c0749a881e8a1f0fb6c350e838b7ffff5985c074c98a06b10af6e902c32c3047 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
