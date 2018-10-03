
rule n26bf_0187e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.0187e448c0000b12"
     cluster="n26bf.0187e448c0000b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="johnnie malicious backdoor"
     md5_hashes="['4c60a34d1bbcd5e6b3283384e30948eb9214b9a5','157a785d747dc663be6d83e23dbe8bb2a810f03d','eeec78f7f4af5974573dc3ab81a0a52802e05db1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.0187e448c0000b12"

   strings:
      $hex_string = { 784550554f52643478435763007a5968476f7237496a75564f774b6f54434c7400466276314d6e3742754a4f585941654e306f450057673363764e3736667073 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
