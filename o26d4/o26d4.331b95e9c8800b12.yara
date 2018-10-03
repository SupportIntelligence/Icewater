
rule o26d4_331b95e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.331b95e9c8800b12"
     cluster="o26d4.331b95e9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="neoreklami razy malicious"
     md5_hashes="['b4c808acd0cfd557a17f664468f3af33c1278652','69bf90a0faceacd612a10d1d80b16a0a9cb901f3','6a12e7328b2145694dfd50a328a510697465501c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.331b95e9c8800b12"

   strings:
      $hex_string = { 00dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f0010070800 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
