
rule j2319_5b9548d0d6bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5b9548d0d6bb0932"
     cluster="j2319.5b9548d0d6bb0932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html script"
     md5_hashes="['bb0eca276a9015718c967f7bb1f73913f5d0dc52','4402e8b3c250df881efee314d181634a69e88801','d9c53504703d9dcfe1357d9ce955e9bf2a85e176']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5b9548d0d6bb0932"

   strings:
      $hex_string = { 757365206d7973716c69206f722050444f20696e737465616420696e203c623e2f7777772f6874646f63732f77303063623835612f616e6e656b656e732d706f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
