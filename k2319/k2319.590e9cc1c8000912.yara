
rule k2319_590e9cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.590e9cc1c8000912"
     cluster="k2319.590e9cc1c8000912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script diplugem plugin"
     md5_hashes="['573ea8525e7006898d4719c58545f845e105a7dd','56c873d9d668de67b33048213fab7999790695e9','aadc28936afd15bc7d613cd414a8b55f09b91d06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.590e9cc1c8000912"

   strings:
      $hex_string = { 612b65334438592e453168295d2866756e6374696f6e28662c6c2c4b297b69662821667c7c21665b65334438592e5a38685d297b72657475726e203b7d3b7377 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
