
rule o26c0_0050ab41d9abd111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.0050ab41d9abd111"
     cluster="o26c0.0050ab41d9abd111"
     cluster_size="170"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaik malicious crypt"
     md5_hashes="['a4605e5df85c801d8e00c22710cb98b2f73fff04','ad578132f69b7140ba53e0591d9d84b2388581ba','4789ba496e60b2d80460811a2c5dd35bf0999234']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.0050ab41d9abd111"

   strings:
      $hex_string = { 0197d5e7b481371c9e8b911977a2a9029ca17cf85fe8e6fe3f7853fa34c6d0f4f3ab1d186741be1227d44b64897951af5723d384bb2ffdde564ae9b8f5506dad }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
