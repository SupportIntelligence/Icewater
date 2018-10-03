
rule o26bb_632da924dda30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632da924dda30932"
     cluster="o26bb.632da924dda30932"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious adload"
     md5_hashes="['3952f2d207229ea20c72cd18721733e50c28c2e1','d6f27e64db4dabcee229e5590a71bf2a8552fb76','6757c94f75e50570485a61fd0f13d605585a4cdb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632da924dda30932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
