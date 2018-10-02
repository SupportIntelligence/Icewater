
rule n26d4_1bc693a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc693a1c2000b16"
     cluster="n26d4.1bc693a1c2000b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker malicious adsf"
     md5_hashes="['0c8b498dfbc61e27aa30bc19f17f7f7f1e3086cd','2882e5eb0b612fd07fbb8c765acc84593e3ec4ee','e29d598d4bf927ad458df6d93e2879c0e4d32ba1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc693a1c2000b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
