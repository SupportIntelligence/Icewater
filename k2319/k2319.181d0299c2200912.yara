
rule k2319_181d0299c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181d0299c2200912"
     cluster="k2319.181d0299c2200912"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['008ccaf0c2c134dfb54d3e9fd8d87de6ceb1a968','16dce670fa88e2a29389aed72394cb58bd695c8d','86f8aa0d8a50a4cd0eec669f2386966d9873996a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181d0299c2200912"

   strings:
      $hex_string = { 39293a2839332c31362e374531292929627265616b7d3b7661722078334d326f3d7b2747367a273a22696a6b222c27543435273a224e222c27483835273a2246 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
