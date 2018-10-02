
rule k2319_311502b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311502b9c8800b12"
     cluster="k2319.311502b9c8800b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c5391090c2315cebe67aacfa564b6946da214b70','0a8cfbfb95fdbd5dc491507ba53c636c827640f7','db3b589e686fd626e28665c4dc5bcf734f0f8cb5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311502b9c8800b12"

   strings:
      $hex_string = { 2e34383345332c313435292929627265616b7d3b666f72287661722077396920696e207131633069297b6966287739692e6c656e6774683d3d3d28307844423e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
