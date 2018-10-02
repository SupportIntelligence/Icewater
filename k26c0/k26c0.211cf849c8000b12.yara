
rule k26c0_211cf849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.211cf849c8000b12"
     cluster="k26c0.211cf849c8000b12"
     cluster_size="96"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="backdoor darkkomet malicious"
     md5_hashes="['a366ca1e8afbbc080d7800f4ccabe1f44c1e381a','3ed0113045992aaa5164a383d96bd5b4fc034f02','5ad369d9faf9d2b84d454aca4d7c0ec8255a7b9b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.211cf849c8000b12"

   strings:
      $hex_string = { 140bd3e03b55f4731e8d7455a48bff0fb73e2bc785c07e0c424183c60203c03b55f472eb8b75dcb8010000008bf8d3e7017de8897dd0394508750d817de8b005 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
