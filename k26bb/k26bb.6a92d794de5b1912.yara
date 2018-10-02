
rule k26bb_6a92d794de5b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d794de5b1912"
     cluster="k26bb.6a92d794de5b1912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo nsis attribute"
     md5_hashes="['ac36ed664678ca5a265df776328ad415d71794b1','50182c4a90bd52d91e543cfcd49063085337ecc1','260b9bcf202a26dc2a298e0ce4ced04f1760ece4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d794de5b1912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
