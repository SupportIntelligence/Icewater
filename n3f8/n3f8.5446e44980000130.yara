
rule n3f8_5446e44980000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5446e44980000130"
     cluster="n3f8.5446e44980000130"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['7d9956e1491bdc37d76022c566a66250092f02ee','1115ece890565a85ea5c106abf5a04d63b04daf0','c158835f4c3a75a8585cc0289fa624ba440de7fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5446e44980000130"

   strings:
      $hex_string = { 792f416e64726f696457617463684578656375746f723b00254c636f6d2f73717561726575702f6c65616b63616e6172792f4275696c64436f6e6669673b0031 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
