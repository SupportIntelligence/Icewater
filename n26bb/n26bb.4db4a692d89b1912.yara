
rule n26bb_4db4a692d89b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4db4a692d89b1912"
     cluster="n26bb.4db4a692d89b1912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious patched susp"
     md5_hashes="['a354c8d69f172d81abd37dc3462a28658a726a2e','3880c9f16f8e3d442c4071c2301426815c6202f0','8247dc0d1d8cd25637e2328ff6e6cb875da74945']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4db4a692d89b1912"

   strings:
      $hex_string = { 5c24088a1b4a88194185d277f203c78946105bc20400b85f1c4500e8cb81030083ec2453568bd98b730c578965f085f6750433ffeb0d8b43142bc66a1c9959f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
