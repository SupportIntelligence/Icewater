
rule n26d4_1bc6b2a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6b2a1c2000b16"
     cluster="n26d4.1bc6b2a1c2000b16"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="heuristic malicious adsf"
     md5_hashes="['6f549dab7c3c73d9e51f0ab0eab0212387808a1a','6d4b2556b1b17b506443f5deac58775fe98f9f80','21d158febe1365d75efda35108f1def65b95e1cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6b2a1c2000b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
