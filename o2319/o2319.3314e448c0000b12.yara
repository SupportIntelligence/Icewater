
rule o2319_3314e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.3314e448c0000b12"
     cluster="o2319.3314e448c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker clickjack html"
     md5_hashes="['c04707d108814f6dbf75d28c5aa39d2a89215f86','45c253b1efbd30b9faafc12d1d3453c91ba50c2c','68844b5fc627edcfe797a9bc58fbffb4b693d49e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.3314e448c0000b12"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
