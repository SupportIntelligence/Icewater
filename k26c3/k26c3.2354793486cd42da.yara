
rule k26c3_2354793486cd42da
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c3.2354793486cd42da"
     cluster="k26c3.2354793486cd42da"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mirai linux backdoor"
     md5_hashes="['f51ec247df998ad7458dec645e11f298d853eebe','51e71804e962c539f880c03b43bd0b65c755141e','a389b68662aabdf160b0f4d21d4d23c6ba5df26a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c3.2354793486cd42da"

   strings:
      $hex_string = { b8c427bfb4c207bfe8053c3fff860920019a0ca001880d6001980c6001aa006028d607bfc48728e013972ae018892920129b2b6011992b20100303ffffb410a3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
