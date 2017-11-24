
rule pfc8_49193949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.49193949c8000932"
     cluster="pfc8.49193949c8000932"
     cluster_size="108"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smsreg riskware androidos"
     md5_hashes="['00a639eef580857f4e02ceb986b88e39','02bb463d8db339c5feb548275989f9ef','23823e21215b43d7a0b8dc62142e2842']"

   strings:
      $hex_string = { 0e129827f51e2283f3618f967b55995f0c45939201bd3b3fdc8819aa7c8b17a8b997e44895ca521cf7d22963114900a7e805e1adff285b8cbe602eb13e8aacba }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
