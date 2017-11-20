
rule k2321_0ac89c542e6b48fa
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ac89c542e6b48fa"
     cluster="k2321.0ac89c542e6b48fa"
     cluster_size="6"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['1e9fda412ead4b353bb46d58bc0cde0c','2120de8f4749e03f2137bec11958c7a9','bfa5bef621dcfef5e36f51b14cb08994']"

   strings:
      $hex_string = { 70bb29794bf7667d0e3ed5b0b8e7c3cf2d933cd7e1d19b118ce09ce4836384a937df042c97af013e959ab3756ceefae65cef7465d8c8155b228a5ff4c234f672 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
