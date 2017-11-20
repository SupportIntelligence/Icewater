
rule k3ec_1b10ca52d3a30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.1b10ca52d3a30b32"
     cluster="k3ec.1b10ca52d3a30b32"
     cluster_size="11"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['4fd132263bd331c7b86510f805bfc0c5','5f93bf8333064922322a17c54aa3e109','e91d79548aaa09741e260783109eff8d']"

   strings:
      $hex_string = { 7771d918eb08c7cac33c94913e84f20f16d71e48ee61add3b875e244ec68c5304df692319fa87abb0eba17af550349e39bad7c022d7d5b52fc8edc5335a73b6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
