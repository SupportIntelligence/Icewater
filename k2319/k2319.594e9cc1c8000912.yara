
rule k2319_594e9cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.594e9cc1c8000912"
     cluster="k2319.594e9cc1c8000912"
     cluster_size="54"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script adplugin"
     md5_hashes="['174b75ccb053edc2081a1302639169c416e95991','b26b421cb489df05a9df5e9f26c61dbded0720ea','f846e15e9ffdaec1a3111a66b3ed160ae2755b1c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.594e9cc1c8000912"

   strings:
      $hex_string = { 612b65334438592e453168295d2866756e6374696f6e28662c6c2c4b297b69662821667c7c21665b65334438592e5a38685d297b72657475726e203b7d3b7377 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
