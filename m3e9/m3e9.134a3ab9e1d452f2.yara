import "hash"

rule m3e9_134a3ab9e1d452f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.134a3ab9e1d452f2"
     cluster="m3e9.134a3ab9e1d452f2"
     cluster_size="85 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e354ac82dd87d37e0c8341a1aa01b970', 'bfa594766dd56025bdee9b8e7e5a91d7', 'b23da0ed2931782d956ed6f23f6bf2dd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(111616,1071) == "8a93f7439e0c171d73020b1b816e0c4f"
}

