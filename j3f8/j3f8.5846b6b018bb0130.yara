
rule j3f8_5846b6b018bb0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5846b6b018bb0130"
     cluster="j3f8.5846b6b018bb0130"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['7f839ef89251e2d88cd3f9ff1732a69fb46448fb','04918f34648973698434895a1a7e0eda21b29726','886791c69051ee6abf2010a58dda619579a645aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5846b6b018bb0130"

   strings:
      $hex_string = { 616c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
