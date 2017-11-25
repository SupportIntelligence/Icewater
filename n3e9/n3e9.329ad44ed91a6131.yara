
rule n3e9_329ad44ed91a6131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.329ad44ed91a6131"
     cluster="n3e9.329ad44ed91a6131"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="multiplug mplug nbqm"
     md5_hashes="['a4bace92f18b7f79b12d0f76cc6d3048','c19a974dc6d1a1a59dbbb4b237aa13e9','d7833503bae1a8c53f37c16f5a181d2a']"

   strings:
      $hex_string = { 3e383e0060030064000000bc30c03008312831483168318831a831c831e431e8310432083228324832543270329032b032d032f032fc32183324334033603380 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
