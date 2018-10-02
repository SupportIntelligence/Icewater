
rule k2319_1a4a96a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a4a96a9c8800b12"
     cluster="k2319.1a4a96a9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['29418308170a2ce0abed5951fc1e3862b839a6f5','d2077181878371bcf4a3a41994f5203433feee8c','dd92d66fb58951be08ece0af14c7227021ed00db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a4a96a9c8800b12"

   strings:
      $hex_string = { 5b795d213d3d756e646566696e6564297b72657475726e20545b795d3b7d76617220563d283131342e3e3d2839302c33392e293f28352e353445322c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
