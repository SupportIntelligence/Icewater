
rule n2319_13db21e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13db21e9c8800b12"
     cluster="n2319.13db21e9c8800b12"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['47c9eab8b59a615373f5b1e9b69b169d5effdd11','1d8741c7ddae840079bafbf274623a24a91a9ddb','34b24a8104db967fb72a2c9c18540fc13724ad20']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13db21e9c8800b12"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
