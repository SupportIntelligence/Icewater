
rule m2319_2b35690cdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b35690cdee30912"
     cluster="m2319.2b35690cdee30912"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['d9f0e1262ab6ff087672d4ec1fd4318609c5c9d4','46a4f55e7cde216bcc826b8c781d6656dbab6ab0','5ef3575f2ed71a8b72c98959531165e242c1b231']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b35690cdee30912"

   strings:
      $hex_string = { 2c655b732b2b5d293d3d3d213129627265616b3b72657475726e20657d2c7472696d3a64262621642e63616c6c2822efbbbfc2a022293f66756e6374696f6e28 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
