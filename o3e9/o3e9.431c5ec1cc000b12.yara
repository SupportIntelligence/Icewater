import "hash"

rule o3e9_431c5ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.431c5ec1cc000b12"
     cluster="o3e9.431c5ec1cc000b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wannacry wannacryptor"
     md5_hashes="['a77d1e53dd2089e2a040c8b96a523132', 'a77d1e53dd2089e2a040c8b96a523132', '9e826957668bf1bf857a63473bdb33d2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(40960,1024) == "e27288d0485e382bc67cd82ed066ecfa"
}

