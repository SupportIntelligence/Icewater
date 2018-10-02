
rule n26d4_1bc6bae1c6000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6bae1c6000b16"
     cluster="n26d4.1bc6bae1c6000b16"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker heuristic malicious"
     md5_hashes="['2c0491732520c98648ec7a5fcb16b0b510d7c272','948d74ee41cc16963fb50e76347952b908aed2f0','d7152213b584668b24d09a4b85688fa45d9bef60']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6bae1c6000b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
