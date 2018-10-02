
rule k2319_311506b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311506b9c8800b12"
     cluster="k2319.311506b9c8800b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4f135bf1a0513134cfd525f8cc46795ef9b94673','4a0c43cbdff89a171a0a27c9523e25472b57a16c','44583a4cceb1157059b0d72f87d6526805b97e57']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311506b9c8800b12"

   strings:
      $hex_string = { 2e34383345332c313435292929627265616b7d3b666f72287661722077396920696e207131633069297b6966287739692e6c656e6774683d3d3d28307844423e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
