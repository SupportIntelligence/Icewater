
rule k3e9_19149fa1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.19149fa1ca000912"
     cluster="k3e9.19149fa1ca000912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['1f2ec4caa52aedfcfd8c3dffe43ac44e','26bcb273f616253a80a592a8949d0dbe','d43b4c159e14c8690276247dd80216d3']"

   strings:
      $hex_string = { 4bb5cbeb5ea1b2ca6cd6c1f3493a561b0399d22788c636fcd95aabb3f54467772a241c62e765c3f414116d5b2515395dd9348df0d5bd661d35fe4637f2a8cfde }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
