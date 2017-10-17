import "hash"

rule m3e9_2b561c5bd32d6916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b561c5bd32d6916"
     cluster="m3e9.2b561c5bd32d6916"
     cluster_size="197 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="michela pioneer minak"
     md5_hashes="['a67c60edf1b93817966e85afa720c2c3', '728db354cc4806ebe4ff04b40f01fa21', '151b798c3aaf8b72825c568d9a5114f3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(190976,1024) == "6375de9f28f38cb9d682b678e82ff74c"
}

