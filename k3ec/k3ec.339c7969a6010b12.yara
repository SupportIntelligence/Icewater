
rule k3ec_339c7969a6010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.339c7969a6010b12"
     cluster="k3ec.339c7969a6010b12"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic malicious engine"
     md5_hashes="['0151bee66abf86dd559421e911c1e26a','4969f068a15d9d4e86b5543b9e20c034','de2c5e0cb95a5f80285021dc05356a6f']"

   strings:
      $hex_string = { 6548616e646c65570031005f5f766372745f4c6f61644c69627261727945785700564352554e54494d45313430442e646c6c0014005f4372744462675265706f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
