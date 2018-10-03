
rule o26bb_6304a160d3930912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6304a160d3930912"
     cluster="o26bb.6304a160d3930912"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['e652bfbc62a300a09bb8ca6a44cbae22c288118d','6914a0bd6ae46aed85c11891133245d2bd88e373','b6e1c389b8aa9dcfec1f96e326b0c7ab2c0968b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6304a160d3930912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
