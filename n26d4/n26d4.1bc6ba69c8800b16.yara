
rule n26d4_1bc6ba69c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6ba69c8800b16"
     cluster="n26d4.1bc6ba69c8800b16"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker malicious adsf"
     md5_hashes="['0d69da6df8f8c45dce0a7e7b60637a057d9bfcb3','1e0ec69e6f5d3103e44544dbce2c2ce3eb30bffd','49abb9b6866a2172d2c379bca74bafed7ea9e8d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6ba69c8800b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
