
rule o26bb_11bbcc89d93b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.11bbcc89d93b0b12"
     cluster="o26bb.11bbcc89d93b0b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adload genx"
     md5_hashes="['b51db59dee8ef594c066902f903eff83f2ba2748','5f6a1b58ff28902e16bd3f407f0145e9497564cf','df84366fa4d58de6ff48b44d4f260dc1e0e79df8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.11bbcc89d93b0b12"

   strings:
      $hex_string = { 4f44454c41593a2025730a00005443505f4e4f44454c4159207365740a0000000073615f6164647220696e65745f6e746f702829206661696c65642077697468 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
