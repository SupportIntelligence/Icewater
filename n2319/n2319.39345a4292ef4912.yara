
rule n2319_39345a4292ef4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39345a4292ef4912"
     cluster="n2319.39345a4292ef4912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['f66f3acb938704e76fe616d81e456bf8b6867f89','d7cca52cdb0a34c6dde784fe7cd2e9818a1f3f2e','e30b625cf8f48efab210483ff1bbfaaf668b29b2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39345a4292ef4912"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
