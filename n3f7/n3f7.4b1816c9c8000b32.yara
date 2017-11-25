
rule n3f7_4b1816c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4b1816c9c8000b32"
     cluster="n3f7.4b1816c9c8000b32"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['088c129af7dac6aceafd7d7536300fe9','10976b106c3c30ff3e39389b45e9c3fc','6136e47e9826b0ca81f3f5264fa4a3db']"

   strings:
      $hex_string = { 46444144393644383433433035463733423743364530423431333730433141393035363841323139363937323739324538454532424631304235343746344243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
