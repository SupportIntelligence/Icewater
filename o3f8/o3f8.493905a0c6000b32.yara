
rule o3f8_493905a0c6000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.493905a0c6000b32"
     cluster="o3f8.493905a0c6000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dnotua risktool"
     md5_hashes="['2a7d3e91b98cd8eac245954f105d982098225ae0','48c5c152273276d87377ec86fd57d8fafcd7fe7e','e1ba0a9f8db9a2dc431e2662434292d75ba0ee2a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.493905a0c6000b32"

   strings:
      $hex_string = { 90c385c2adc2843740c38fc3a25872c3bd4e49423409020301c08001c2a350304e301d0603551d0e041604147ac3b47e3d214ac2872f5826482a673ac3871843 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
