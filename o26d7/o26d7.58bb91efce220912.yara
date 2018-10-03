
rule o26d7_58bb91efce220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.58bb91efce220912"
     cluster="o26d7.58bb91efce220912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious downloadsponsor ocna"
     md5_hashes="['1a953fc40f67218b204203e92963eea66a3f91b4','fcef42db7da74a4738e02f23d83eae00e617c252','8d17f6b186866f0fbab446f55155146c55dbc262']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.58bb91efce220912"

   strings:
      $hex_string = { f8bf60514b0033f6b0050fb6d83bd37513528bd7e83c7ff9ff5985c0741c8b55fc8b4df88a86014e4b004703fb4684c075d883c8ff5f5e5bc9c38bc6ebf75356 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
