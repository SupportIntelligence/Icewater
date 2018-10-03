
rule j2319_5b9548d0dceb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5b9548d0dceb0932"
     cluster="j2319.5b9548d0dceb0932"
     cluster_size="329"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html iframe"
     md5_hashes="['5f04ac23dfd7966185ae042118b1bbf1bfab1e03','95bdfbc357f2656509106ec91ac554792b57b90a','6829a9673b0de3ab21135f59b8129e1b80b276d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5b9548d0dceb0932"

   strings:
      $hex_string = { 757365206d7973716c69206f722050444f20696e737465616420696e203c623e2f7777772f6874646f63732f77303063623835612f616e6e656b656e732d706f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
