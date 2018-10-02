
rule n231d_2b993949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.2b993949c0000b32"
     cluster="n231d.2b993949c0000b32"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddenapp blackcert"
     md5_hashes="['7c726f2475a26ca623555a5fa82358472df82c38','eb70a1a7cce3cd5209842d3902d3c43bc568e83a','b62414c02dd46ce2f298c3aa0c7300d259811fb9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.2b993949c0000b32"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
