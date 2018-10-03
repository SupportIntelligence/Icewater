
rule j2319_5b9548d0db8f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5b9548d0db8f4932"
     cluster="j2319.5b9548d0db8f4932"
     cluster_size="243"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html script"
     md5_hashes="['3e376c0fab2c64446b11edf26e1f40a7fa5545f8','7e48844667a85a20488bc2416ef46bc2c9b95bcd','d62a0f31aaf64e7dc128d6c379440b19a1fba2e4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5b9548d0db8f4932"

   strings:
      $hex_string = { 757365206d7973716c69206f722050444f20696e737465616420696e203c623e2f7777772f6874646f63732f77303063623835612f616e6e656b656e732d706f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
