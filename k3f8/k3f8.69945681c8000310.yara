
rule k3f8_69945681c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.69945681c8000310"
     cluster="k3f8.69945681c8000310"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos boogr"
     md5_hashes="['e9eecfc707428f86ec11b1440cd7dd6a11c8f3e6','5a73b40a19388abf592ede79f2d148fa320f68d8','5f7368bd71ae0b6a9274e0f8b199f1831e6a9b6e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.69945681c8000310"

   strings:
      $hex_string = { 4275696c6465723b00124c6a6176612f6c616e672f53797374656d3b002b4c6a6176612f6c616e672f54687265616424556e636175676874457863657074696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
