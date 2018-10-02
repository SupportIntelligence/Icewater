
rule k2319_311506e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311506e9c8800b12"
     cluster="k2319.311506e9c8800b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['fd619533085f4b30aa4924e3605c045362a150ac','852880bf4a3498d9b0f2a8e31e78652243fc85ec','b36067cef48c1554f27758e05bf9baefce59804d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311506e9c8800b12"

   strings:
      $hex_string = { 2e34383345332c313435292929627265616b7d3b666f72287661722077396920696e207131633069297b6966287739692e6c656e6774683d3d3d28307844423e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
