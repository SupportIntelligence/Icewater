
rule j26bf_1896ec4ec6630930
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.1896ec4ec6630930"
     cluster="j26bf.1896ec4ec6630930"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo genx malicious"
     md5_hashes="['6852129f6de97c86d873bb7e3395eaac47d63d1d','5876b92a5020849f8418825da043faac3970ab3f','1a17076af406a6b11bd0151482463071f420b501']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.1896ec4ec6630930"

   strings:
      $hex_string = { 756c740044656661756c740073656e646572006500646973706f73696e670076616c75650053797374656d2e5265666c656374696f6e00417373656d626c7954 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
