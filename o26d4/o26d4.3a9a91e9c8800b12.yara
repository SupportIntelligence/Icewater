
rule o26d4_3a9a91e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.3a9a91e9c8800b12"
     cluster="o26d4.3a9a91e9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy neoreklami malicious"
     md5_hashes="['76dac278565e5bc669ee30ca9c0d8e2ebe338298','627e8590a2f4ff524bbf2828511c7d555c6aa6a5','94bb61e3788cffe1fdd29f6ef0b8a22702438004']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.3a9a91e9c8800b12"

   strings:
      $hex_string = { 0033c9538b5d0c2bd843d1eb3b450c568b75100f47d985db74238bf80fb70750ffd28b55f48d7f0266890683c6028b45fc408945fc593bc375e28b7df089375e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
