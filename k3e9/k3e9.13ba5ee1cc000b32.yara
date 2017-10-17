import "hash"

rule k3e9_13ba5ee1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ba5ee1cc000b32"
     cluster="k3e9.13ba5ee1cc000b32"
     cluster_size="106 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd upatre bublik"
     md5_hashes="['bbc38db16a25b95b39f21d7741bf77fe', 'a74c8289b14b69c02118924701a9bb97', 'a35f7e6a2ed41f4bf8266c64ba61675c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15872,1088) == "a5318e3e5c474df2b5a9058f4d352222"
}

