import "hash"

rule o3e9_2d1268d296927b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2d1268d296927b92"
     cluster="o3e9.2d1268d296927b92"
     cluster_size="2019 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="dlboost installmonster installmonstr"
     md5_hashes="['05be85faa23a8ea3e2037891daf855ed', '21c6a844f5831dd31a98d019be27e5bc', '1a7fca04df094ccf267dba6ed5e0c89e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2506789,1061) == "9db134f8aff7face05774baeba29e70d"
}

