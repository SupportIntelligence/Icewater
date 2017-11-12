import "hash"

rule o3e9_1651284ad6d26b9e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1651284ad6d26b9e"
     cluster="o3e9.1651284ad6d26b9e"
     cluster_size="820 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['2a2057a54961f2eca9b0f421468a5958', '54753459f39c3ce7e44edcdc5ebcd529', '3077ac6a2187fdd285568e01e5e1f931']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3076096,1024) == "61d80e3c42d74556c601a83fe9d15f51"
}

