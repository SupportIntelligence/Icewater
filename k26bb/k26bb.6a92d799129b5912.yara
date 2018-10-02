
rule k26bb_6a92d799129b5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d799129b5912"
     cluster="k26bb.6a92d799129b5912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis attribute"
     md5_hashes="['138730681bb2a3f875c5d190e8df78e8218399ea','c2015bc478d202637697fd46f38e9d03f83cb6ef','9a086631adf874b58a10080063ca7d5a47be57d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d799129b5912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
