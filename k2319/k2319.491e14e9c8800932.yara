
rule k2319_491e14e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.491e14e9c8800932"
     cluster="k2319.491e14e9c8800932"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browsermodifier"
     md5_hashes="['08faf9e825f6518875ac6cbd97ccbf146780da2f','6f7678a882dfab7a32dfcffde5b457522d9ea0a5','1927b0366e66e75cebbd5384af69a981c5b5d5cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.491e14e9c8800932"

   strings:
      $hex_string = { 32492e4639493b7d2c65373a66756e6374696f6e284e2c512c74297b76617220793d22773249222c473d282831302e363945322c3131332e293c3133383f2835 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
