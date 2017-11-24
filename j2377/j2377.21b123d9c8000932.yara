
rule j2377_21b123d9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.21b123d9c8000932"
     cluster="j2377.21b123d9c8000932"
     cluster_size="14"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html exploit iframe"
     md5_hashes="['21e7ab88a8b121604e96a3454106515f','25a3591eea2e5801577ed417e66f2ff7','f9d85041f8eed65e06eda075badde549']"

   strings:
      $hex_string = { 6764297b787a2873297d3c2f7363726970743e3c212d2d2f6235626565312d2d3e0a0a3c7469746c653ed0a0d0b5d184d0b5d180d0b0d182d18b2c20d0b3d0b4 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
