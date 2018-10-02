
rule k26bb_7a9243d9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.7a9243d9c2200b12"
     cluster="k26bb.7a9243d9c2200b12"
     cluster_size="102463"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd malicious eikqad"
     md5_hashes="['5e44a2863aadaddd7e97f56d6644ae1a85c94974','4f9810c69eb5ce628859c69511b0a0f67c48e2a5','114b4d5a0141986bacee1d36828b59bfc5b9ca3c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.7a9243d9c2200b12"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a1c83e42005633f683f92073343935cc3e4200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
