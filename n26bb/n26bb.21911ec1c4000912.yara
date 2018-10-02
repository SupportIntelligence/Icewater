
rule n26bb_21911ec1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.21911ec1c4000912"
     cluster="n26bb.21911ec1c4000912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious eadz injector"
     md5_hashes="['063964f084a0c85ff9f2d0c3014e667734cd8871','bdc9f46f57ed123e311f9026038e38bd750078bb','2496b29da4857ce2077ccbb5f64838cc829a5d39']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.21911ec1c4000912"

   strings:
      $hex_string = { 0d5c5e0f86ceadbfa0162922cfbb6a1ca5803311255278a461cd8b73132aaa1ba6fab4c84fbef86206b3207203e798f4454eea418dd2cb48309d76b8914c8921 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
