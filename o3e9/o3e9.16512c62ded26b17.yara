import "hash"

rule o3e9_16512c62ded26b17
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16512c62ded26b17"
     cluster="o3e9.16512c62ded26b17"
     cluster_size="309 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['4ea0887ef7ad7fdced83a32be548d4cb', 'ca8685ca542d53172776971243d2af6e', 'ae1eb29d9eb0fadc5bcace80e8a15031']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2689024,1024) == "6e8cfd767e54ddadc2ac86e63152c716"
}

