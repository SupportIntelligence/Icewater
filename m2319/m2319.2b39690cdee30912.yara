
rule m2319_2b39690cdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b39690cdee30912"
     cluster="m2319.2b39690cdee30912"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['cb7ecfb27177940aab2e5cd1526a5f155c138754','74753db592869d244a125848d98cee21d1749161','0911cfb417a0202ebf596f52ea49a09b146feb94']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b39690cdee30912"

   strings:
      $hex_string = { 732c655b732b2b5d293d3d3d213129627265616b3b72657475726e20657d2c7472696d3a64262621642e63616c6c2822efbbbfc2a022293f66756e6374696f6e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
