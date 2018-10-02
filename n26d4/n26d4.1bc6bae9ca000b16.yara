
rule n26d4_1bc6bae9ca000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.1bc6bae9ca000b16"
     cluster="n26d4.1bc6bae9ca000b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker filerepmetagen adsf"
     md5_hashes="['352fe549487e4aa6c85c975d2939819a2b13ff20','149c4e579bf79cceea09b908344587830d4ceb72','6bf27db460688773f6947ff2a4dc44287c92d620']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.1bc6bae9ca000b16"

   strings:
      $hex_string = { cc303d0218b53e0210545265736f757263654d616e616765728d400089d189c231c066c1c0053202424975f6c38d4000535684d2740883c4f0e83a7ffeff8bda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
