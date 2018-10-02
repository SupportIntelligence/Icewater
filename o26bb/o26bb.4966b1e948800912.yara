
rule o26bb_4966b1e948800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4966b1e948800912"
     cluster="o26bb.4966b1e948800912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nymeria malicious autoit"
     md5_hashes="['50b9610ff324cd02008a6a4a6b76d3c7895c292f','a97e00389105eab3b22dd151acbb98c4dc4df9ba','30ffa12e4f5844f0ed4958ec38f1be812db65654']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4966b1e948800912"

   strings:
      $hex_string = { f8bf60514b0033f6b0050fb6d83bd37513528bd7e83c7ff9ff5985c0741c8b55fc8b4df88a86014e4b004703fb4684c075d883c8ff5f5e5bc9c38bc6ebf75356 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
