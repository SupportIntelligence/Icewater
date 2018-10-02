
rule k26bb_6a92d7981a3b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6a92d7981a3b0912"
     cluster="k26bb.6a92d7981a3b0912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo filerepmetagen nsis"
     md5_hashes="['6b38bba55eba4b03eca77f73c19a67afe4493501','06e9331c05c1f69a161082487bfe5cbdd5bab99c','285f900d92d078e21a672561925dd3ea95015990']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6a92d7981a3b0912"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a188eb42005633f683f920733439358ceb4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
