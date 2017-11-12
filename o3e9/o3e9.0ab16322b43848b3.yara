
rule o3e9_0ab16322b43848b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0ab16322b43848b3"
     cluster="o3e9.0ab16322b43848b3"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler malicious"
     md5_hashes="['13b0191cbd0ccded83edf7c0ba9ea2c0','143df96822f737130f040f23f0384d1e','fba99ff11127e0f390ca45af5518bc20']"

   strings:
      $hex_string = { 5a0e17caddab424ec534bd863f5848509ead89683a8fcd8bdeaa14558166d3e329b16e3974536d134122c0085f7f0665bfa4e5c88798f0f88efea9d2a6ae9611 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
