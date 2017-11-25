
rule p3f1_111aa54bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f1.111aa54bc6220b12"
     cluster="p3f1.111aa54bc6220b12"
     cluster_size="24"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd triada androidos"
     md5_hashes="['0dfd54d6c78b9b5951d7987c74ae65bc','14d60fe93d90b74e0bc7e320e9055fe2','a5965f19d121b1a621cbfb45cab2f735']"

   strings:
      $hex_string = { bffcba7895c0b408fe7c067fffde23e7a4f51a2bbd25917e50485f77aaf8dcd68aeee27a6eb6d43bb782a9e49ccc1563266b7519d3c214f157cdc852c13d17fa }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
