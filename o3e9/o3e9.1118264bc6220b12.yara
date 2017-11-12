import "hash"

rule o3e9_1118264bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1118264bc6220b12"
     cluster="o3e9.1118264bc6220b12"
     cluster_size="324 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmetrix applicunwnt"
     md5_hashes="['71b2aa8d944ab5b806061ff07d23a86c', '629a434b8f54254c56510baadb040445', 'f07ef4525d3f21645e38c03f91b50b57']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2052608,1024) == "5219997592f1d69fe6ded0293050b7e1"
}

