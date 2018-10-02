
rule k26bb_6a92d79c9a2b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d79c9a2b1912"
     cluster="k26bb.6a92d79c9a2b1912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo filerepmalware nsis"
     md5_hashes="['9a33d9765f606f01c433c3d2d09beb9be5904936','500e7d0c5ef457d214100abac188f56708cf610e','cb38b9c093c6e6ff95b00073955477c4497e5471']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d79c9a2b1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
