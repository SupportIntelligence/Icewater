import "hash"

rule o3e9_2b136c968c52f1b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b136c968c52f1b2"
     cluster="o3e9.2b136c968c52f1b2"
     cluster_size="402 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor installmonster installmonstr"
     md5_hashes="['40b1ae50b7fac7dc8fadb44062b69b8c', '7d287d864e12ccdc02bd280093d09b5d', '7c578d07a7b3a0b22052f62676f7a10f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2509437,1029) == "84e9f1d761f6f5e396bbfc033dd859bd"
}

