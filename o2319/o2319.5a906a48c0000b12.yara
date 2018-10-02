
rule o2319_5a906a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.5a906a48c0000b12"
     cluster="o2319.5a906a48c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer script coinhive"
     md5_hashes="['e3865eb598354a1c411a5375c30f233cf7ccce5f','cfa78ab848e6d8c8b9fbf61b6c75684a87e9a34e','0920e4c293f66c18e8f1baafb4404693d2e1a238']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.5a906a48c0000b12"

   strings:
      $hex_string = { 626c6f636b554928746869732e6470446976293b0a09097d0a0909242e6461746128746869732e5f6469616c6f67496e7075745b305d2c2050524f505f4e414d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
