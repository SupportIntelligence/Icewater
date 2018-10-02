
rule k2319_1a1a9cb9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1a9cb9c2200b12"
     cluster="k2319.1a1a9cb9c2200b12"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['803defc0c24dba366caf1726ac3178c1705bfbdb','6d1668d1c39eeea24df253e60a288ff79584ad17','9d95531222f1249dd9067d18b490a52d2d018ddd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1a9cb9c2200b12"

   strings:
      $hex_string = { 646f773b666f72287661722056374220696e207735773742297b6966285637422e6c656e6774683d3d3d2828307843462c3536293c3d332e383945323f283078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
