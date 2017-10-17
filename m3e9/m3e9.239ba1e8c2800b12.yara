import "hash"

rule m3e9_239ba1e8c2800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.239ba1e8c2800b12"
     cluster="m3e9.239ba1e8c2800b12"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['f7470747ed217f1984083bd3a7fa7ad4', '91fe870da7c8cee9ab22c35a48f8fd72', '91fe870da7c8cee9ab22c35a48f8fd72']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

