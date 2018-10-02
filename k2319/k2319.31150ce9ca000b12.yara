
rule k2319_31150ce9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.31150ce9ca000b12"
     cluster="k2319.31150ce9ca000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4c5619916a285e841e0c1d0c7c10fde31921bef1','29a02701d0b95266961cfccdb0811b8c1f4037be','f2bdb62a33c02543d08510f76961d140ed0c9989']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.31150ce9ca000b12"

   strings:
      $hex_string = { 2e34383345332c313435292929627265616b7d3b666f72287661722077396920696e207131633069297b6966287739692e6c656e6774683d3d3d28307844423e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
