
rule k26bb_6a92d794da5b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d794da5b0912"
     cluster="k26bb.6a92d794da5b0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis classic"
     md5_hashes="['42f7f68fedde0c916b96fb4d23a153e1824a3709','80c997e42bca869e30dc5d1531655fd3c2735e91','2734d730c270fb599a2822701c55935068ed4291']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d794da5b0912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
