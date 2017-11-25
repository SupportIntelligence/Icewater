
rule k2321_5b10ca52d3a30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.5b10ca52d3a30b32"
     cluster="k2321.5b10ca52d3a30b32"
     cluster_size="3"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['a0a1bf72fbfa77afd423a028791a67e7','a6febfb1ec673402eec16c45c02ff1d5','eb3e3f58f747437f582efc3edd0efdb7']"

   strings:
      $hex_string = { 7771d918eb08c7cac33c94913e84f20f16d71e48ee61add3b875e244ec68c5304df692319fa87abb0eba17af550349e39bad7c022d7d5b52fc8edc5335a73b6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
