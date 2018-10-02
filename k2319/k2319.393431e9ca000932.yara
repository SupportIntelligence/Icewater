
rule k2319_393431e9ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393431e9ca000932"
     cluster="k2319.393431e9ca000932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['63c95195e1a4506cbc9e6e20d10c5bcd0ce4b383','54bbae86dde8a3246f84b7907778c337b7ba456a','fabfb73ad32241f2844402defdf27239efe4373f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393431e9ca000932"

   strings:
      $hex_string = { 465b495d213d3d756e646566696e6564297b72657475726e20465b495d3b7d766172206b3d2828307836302c3078323534293e35382e3f28312e30383745332c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
