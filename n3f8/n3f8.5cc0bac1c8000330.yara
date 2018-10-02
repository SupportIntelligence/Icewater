
rule n3f8_5cc0bac1c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5cc0bac1c8000330"
     cluster="n3f8.5cc0bac1c8000330"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['d26cf36cebea66222f37f94a8c7ec0005b5464f3','e2a5259390b250e9d3825bc1988089df3b9b53c0','b18039cad094827949ff5dba3dfc82c235a26a36']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5cc0bac1c8000330"

   strings:
      $hex_string = { 50696e673b00344c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f6672616d65642f507573684f6273657276657224313b00324c636f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
