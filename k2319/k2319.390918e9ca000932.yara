
rule k2319_390918e9ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.390918e9ca000932"
     cluster="k2319.390918e9ca000932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e28ca8bbe3852d1e2e3c73c438700160684c9d06','8c1041705c304c51a6932c2d7bac67739d99831a','7e4a777ac93471fcf78391409d975e2937325c07']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.390918e9ca000932"

   strings:
      $hex_string = { 29627265616b7d3b666f72287661722057344120696e206938533441297b6966285734412e6c656e6774683d3d3d282830783141462c33352e324531293c2837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
