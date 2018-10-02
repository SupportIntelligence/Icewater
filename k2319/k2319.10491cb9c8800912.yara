
rule k2319_10491cb9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10491cb9c8800912"
     cluster="k2319.10491cb9c8800912"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1f87524c93a2f5c9b7e2fec1cdf891637bbb7bab','a3203dd32631dfdf30d86f7541b5dee64f2addbb','853c793a5bf516dbac9ec282dac04e855e4533d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10491cb9c8800912"

   strings:
      $hex_string = { 307846372c313333292929627265616b7d3b766172204b3068316c3d7b27423965273a226462222c2766336c273a66756e6374696f6e284f2c45297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
