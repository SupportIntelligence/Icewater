
rule o26d7_58bb903a1ee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.58bb903a1ee31912"
     cluster="o26d7.58bb903a1ee31912"
     cluster_size="84"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious susp"
     md5_hashes="['eb984d0ed132ed2238778b3b2e2d8e82a32c5276','bf78c3ed6a0a7605722cac1b85a510374cce17a9','d59a39d71b58b411281e3a5d6e96a67ae028d4b0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.58bb903a1ee31912"

   strings:
      $hex_string = { f8bf60514b0033f6b0050fb6d83bd37513528bd7e83c7ff9ff5985c0741c8b55fc8b4df88a86014e4b004703fb4684c075d883c8ff5f5e5bc9c38bc6ebf75356 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
