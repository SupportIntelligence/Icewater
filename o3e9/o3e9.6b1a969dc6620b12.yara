import "hash"

rule o3e9_6b1a969dc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6b1a969dc6620b12"
     cluster="o3e9.6b1a969dc6620b12"
     cluster_size="111 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster loadmoney installmonstr"
     md5_hashes="['90a1d07173c19ae0fe9d74a878df5ad7', 'f4eac2c7dd0518cba47111d1fb7468d6', '9aa571fcdbaba92d345f00330cc79044']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(776192,1024) == "3f59512cb237b37c0f75b21d11ad2176"
}

