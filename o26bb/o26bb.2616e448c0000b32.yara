
rule o26bb_2616e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2616e448c0000b32"
     cluster="o26bb.2616e448c0000b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious patched"
     md5_hashes="['5e245718d3453e82739a0d475685ea68eccb0f05','25c5fd5683d112aabbe96d8253c2883095916d6d','f11a29551157103e55c4c356be54166fb4dcda30']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2616e448c0000b32"

   strings:
      $hex_string = { 5c24088a1b4a88194185d277f203c78946105bc20400b85f1c4500e8cb81030083ec2453568bd98b730c578965f085f6750433ffeb0d8b43142bc66a1c9959f7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
