
rule n2319_2dd0709dcf4f4b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2dd0709dcf4f4b32"
     cluster="n2319.2dd0709dcf4f4b32"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner script"
     md5_hashes="['df914167e933b7855829ee171debba15aafd69df','7ef44d53fe518ab4d1fcd068f3eb393818c1667a','d2fd7a8ca7bf3543d6c436e95036cebc94ee7aa4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2dd0709dcf4f4b32"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
