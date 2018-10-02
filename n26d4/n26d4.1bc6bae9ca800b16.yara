
rule n26d4_1bc6bae9ca800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6bae9ca800b16"
     cluster="n26d4.1bc6bae9ca800b16"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="heuristic malicious adsf"
     md5_hashes="['a3c25cf56f948e75f349cb0b41a7a32e1f1432d1','15eed21060341c9c6c8eb36994be6216f93b5f37','f591a757d07ed778516eb3f17ea62bcf8807e190']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6bae9ca800b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
