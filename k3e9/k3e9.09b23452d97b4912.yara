
rule k3e9_09b23452d97b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09b23452d97b4912"
     cluster="k3e9.09b23452d97b4912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['195309cce76847c6c0b61ffec6eb1a46','1f615fb292e3d54bf53c250e9829f1d1','eaad5744cffebd7e7136d8a2d7116fee']"

   strings:
      $hex_string = { 2d50f70eb5f461cf4d7246a83ad3dd7a81e38983e028d738a25391295a701d0467e654f5e42c621141d0d0b6d41536c2d9efd89e6afb1fc05fed09c7d27b80fe }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
