
rule m3f7_19999cc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.19999cc9c4000b32"
     cluster="m3f7.19999cc9c4000b32"
     cluster_size="53"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0a5c9d352b4b7f8a58f38e025e721da7','0ca9c8445cb253213c67a79623246866','524f203a73f8488d99a2b3a4339a47e5']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d34353230363230353138343837323639353326776964676574547970653d48544d4c2677696467657449 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
