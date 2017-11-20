
rule k3e9_69d09ce919eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce919eb0b12"
     cluster="k3e9.69d09ce919eb0b12"
     cluster_size="419"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark webtoolbar"
     md5_hashes="['001c7a6da5fe99238b5abc1bc1906af7','004d4c3d48311429b05d6247a50d5709','114e0bc53203af11a563adf992903733']"

   strings:
      $hex_string = { b622bc6ebeef95a41dd0a957bd7ad4b8eefcf1fd0cb919ea1bd6f75d3df86a7fbb59e5aa53c65a0f949172f0977d6160da8cf4f62c74dea1346c8499e980b345 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
