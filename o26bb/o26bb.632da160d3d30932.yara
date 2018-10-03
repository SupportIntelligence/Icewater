
rule o26bb_632da160d3d30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da160d3d30932"
     cluster="o26bb.632da160d3d30932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious malwarex"
     md5_hashes="['d88ee77d4451db536f2edbaef7b5e0f368cce722','672c7ebef17f8f1979f1944186500179cdac83e4','de7265563a16be65f11eefd1885cd4bf42cd0eb9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da160d3d30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
