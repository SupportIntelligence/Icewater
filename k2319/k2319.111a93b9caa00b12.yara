
rule k2319_111a93b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.111a93b9caa00b12"
     cluster="k2319.111a93b9caa00b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b29d6259fbece951bd31963b0ad9bb24dd2b5100','83be3a997008ff2d23671903ffde9fb7b87110a3','5a4bf707bb82b9eee5addbc0f396c1c807feb6ac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.111a93b9caa00b12"

   strings:
      $hex_string = { 2833372e2c382e304532292929627265616b7d3b7661722056316c33463d7b2770394f273a2267222c276e3346273a66756e6374696f6e28442c79297b726574 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
