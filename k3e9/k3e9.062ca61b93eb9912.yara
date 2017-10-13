import "hash"

rule k3e9_062ca61b93eb9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.062ca61b93eb9912"
     cluster="k3e9.062ca61b93eb9912"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor qukart berbew"
     md5_hashes="['af1498d27303fcf5b4a260a73df43ab4', '085e5f69ca822b3d31ce3c4e8ba51113', '737a12d91fe3b3a5d9077574bd2f6900']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

