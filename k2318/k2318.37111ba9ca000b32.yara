
rule k2318_37111ba9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37111ba9ca000b32"
     cluster="k2318.37111ba9ca000b32"
     cluster_size="159"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['8def6f672c3c863b0a2068a6cf4a6b751df063a8','3f7c541e2549ca8c02292b9e2985301294c200c0','4dd583162d7f034a3e49f69ee70c7bd72b782372']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37111ba9ca000b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
