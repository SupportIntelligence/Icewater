
rule n26bb_539e91e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.539e91e9c8800b32"
     cluster="n26bb.539e91e9c8800b32"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack airpzlfi patched"
     md5_hashes="['5d589174a15b8eae6c498126ca9aee75dae9e0c9','e93040faf849adc7d644d779aa955db94edcf0c4','394ef42a0520faeaaf9d4160de4c6d597b689354']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.539e91e9c8800b32"

   strings:
      $hex_string = { d58b46408b4e3cebb6e868f8ffff84c074c78b432485c074c08b57088b4b2851c1e204035318508b46205250e8c5fdffff83c410eba38b4de4c6411c01c745fc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
