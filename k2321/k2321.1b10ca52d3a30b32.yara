
rule k2321_1b10ca52d3a30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b10ca52d3a30b32"
     cluster="k2321.1b10ca52d3a30b32"
     cluster_size="50"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['0e2a97086b62ed36829c56bbc367ec09','116eaac7932e7ec6e3c7d1d47ef719bc','6a6ff97a95dcf0c2e5cb574c133eb3a6']"

   strings:
      $hex_string = { 7771d918eb08c7cac33c94913e84f20f16d71e48ee61add3b875e244ec68c5304df692319fa87abb0eba17af550349e39bad7c022d7d5b52fc8edc5335a73b6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
