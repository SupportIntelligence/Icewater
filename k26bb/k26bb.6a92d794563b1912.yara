
rule k26bb_6a92d794563b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d794563b1912"
     cluster="k26bb.6a92d794563b1912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis attribute"
     md5_hashes="['7e095ce8901f087f78b0e26346dab82ce69b972b','f9c4b0901f0b1789dc03b896e58638aa2cd47941','b4e55c18a4335f8a2a8ece9a8aee136a466ee3bd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d794563b1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
