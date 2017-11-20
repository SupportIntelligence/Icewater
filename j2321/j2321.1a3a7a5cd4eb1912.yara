
rule j2321_1a3a7a5cd4eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.1a3a7a5cd4eb1912"
     cluster="j2321.1a3a7a5cd4eb1912"
     cluster_size="8"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="spyeyes upatre waski"
     md5_hashes="['10cbfce747f1493f7d912645946815a6','37a8d20df224ade3240743dde277f8b2','d3eaff800077aee311170fa1effc4f40']"

   strings:
      $hex_string = { a824f017f48f904b84965e7fef2b4237d439129d751572f762cc84189fb6a63aec4dcf40c8a0855b4ce77a803b6388c828a7b3f2e0347968e597f68b215d7243 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
