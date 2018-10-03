
rule j2319_5b9548d0cb6b9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5b9548d0cb6b9932"
     cluster="j2319.5b9548d0cb6b9932"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html script"
     md5_hashes="['400056a3e46bfcfb51b1e459397dce2007791db5','5381313d999d3452993ed0c1f0abb03144ec8615','552835ac9bfc06be59ff2c11f57949a90ab6548c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5b9548d0cb6b9932"

   strings:
      $hex_string = { 757365206d7973716c69206f722050444f20696e737465616420696e203c623e2f7777772f6874646f63732f77303063623835612f616e6e656b656e732d706f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
