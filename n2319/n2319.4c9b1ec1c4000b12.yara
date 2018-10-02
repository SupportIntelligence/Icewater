
rule n2319_4c9b1ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4c9b1ec1c4000b12"
     cluster="n2319.4c9b1ec1c4000b12"
     cluster_size="55"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitcoinminer miner coinhive"
     md5_hashes="['895a797d9a719da2a7d1b8a06517045fbea4235c','79863d34f6dab044f08a400b4512f59b29f582e5','c7e8f025964a6e6d1d13e01221be8a37e0ab1101']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4c9b1ec1c4000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
