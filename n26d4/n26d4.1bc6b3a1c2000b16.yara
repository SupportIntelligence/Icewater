
rule n26d4_1bc6b3a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6b3a1c2000b16"
     cluster="n26d4.1bc6b3a1c2000b16"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker adsf attribute"
     md5_hashes="['7d24a6f34ab4cb31531b7605d72cbcaddf803197','e91148cf57f29f07216a06cbd3c265481c2660e8','6432efb331a7f4661d34a6dff76831e1e5e58331']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6b3a1c2000b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
