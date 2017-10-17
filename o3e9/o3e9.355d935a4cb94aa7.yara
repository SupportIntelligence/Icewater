import "hash"

rule o3e9_355d935a4cb94aa7
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.355d935a4cb94aa7"
     cluster="o3e9.355d935a4cb94aa7"
     cluster_size="190 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt manbat eyestye"
     md5_hashes="['c11643a8fb2fd436944dfa99519f7e33', 'f944512bee5f92b4ffedc8477691387f', 'f88f7827f1d5ed58d7638c55846b71e1']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(4101120,1195) == "25964e9ad4c4774d5ec1b6342963ef4f"
}

