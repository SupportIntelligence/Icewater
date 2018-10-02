
rule k2319_5e1296e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5e1296e9c8800b12"
     cluster="k2319.5e1296e9c8800b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5f7bc812bc70c72e176d619930c5372ef2615851','8ec6c3bec6bba7a50bbc1b523d5c1c0a6e35ab6d','2c9a537bebda45f9549896ca91652a7d55ae7c61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5e1296e9c8800b12"

   strings:
      $hex_string = { 627265616b7d3b666f72287661722046317520696e207730523175297b6966284631752e6c656e6774683d3d3d282830783141442c3133392e354531293e3735 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
