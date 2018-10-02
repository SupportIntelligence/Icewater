
rule k2319_39091ce9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39091ce9c8000932"
     cluster="k2319.39091ce9c8000932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5e34db67c42bcf47f2474bff2ba5168cb7bd1c44','9069822c8136f8e93cc6dfbe3465ca2920963b2e','cf2a3963365353ac8f2e4a8ffb84e510b33fa99d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39091ce9c8000932"

   strings:
      $hex_string = { 29627265616b7d3b666f72287661722057344120696e206938533441297b6966285734412e6c656e6774683d3d3d282830783141462c33352e324531293c2837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
