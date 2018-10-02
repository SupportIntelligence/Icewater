
rule k2319_190996e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.190996e9c8800932"
     cluster="k2319.190996e9c8800932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5a2c78186bae36648b11014a65b3f5b2e50e2848','b25e90347ecf58010a7cf093ac37b69cc98ccc70','0b8193a1978c7cf613ff9db987fc0ba9398c164f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.190996e9c8800932"

   strings:
      $hex_string = { 3a2834332e3245312c37362e38304531292929627265616b7d3b766172205435533d7b274836273a66756e6374696f6e286b2c42297b72657475726e206b213d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
