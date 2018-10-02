
rule n231d_2b193949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.2b193949c0000b32"
     cluster="n231d.2b193949c0000b32"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['712c9e42d96d7ec8bc4ecbc2ace8fca23cc715cd','d6540163088a0b97dd8b8d93c4cd787d03044bfa','233667dfcb87317e03dfc5fe45e1349d4f9c6b67']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.2b193949c0000b32"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
