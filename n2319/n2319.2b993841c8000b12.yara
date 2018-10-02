
rule n2319_2b993841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2b993841c8000b12"
     cluster="n2319.2b993841c8000b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack clickjack faceliker"
     md5_hashes="['74dc715281712691c7f3c56f057a01723f8c5c08','92a29c1e5c0e00f3a008fb05aafa75f693523330','5ce2b540f8cc2abb55364eb9a964dde527c57e22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2b993841c8000b12"

   strings:
      $hex_string = { 297d3b766172206b623d6465636f64655552492822253733637269707422292c6c623d2f5e5b2d2b5f302d395c2f412d5a612d7a5d2b3d7b302c327d242f2c6d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
