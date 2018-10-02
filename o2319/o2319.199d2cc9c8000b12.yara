
rule o2319_199d2cc9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.199d2cc9c8000b12"
     cluster="o2319.199d2cc9c8000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer miner"
     md5_hashes="['c10203e3206fa932ddbc2be0c075bdc40a6242bc','9d8e7470cce0816d57fbd53be5113acc3c7a98da','5c67f9b3701d62be21bae47a8ee8dba80b8b5451']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.199d2cc9c8000b12"

   strings:
      $hex_string = { 494d455354414d503a2240222c5733433a2279792d6d6d2d6464222c5f7469636b73546f313937303a32342a283731383638352b4d6174682e666c6f6f722834 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
