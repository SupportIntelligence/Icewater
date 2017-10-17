import "hash"

rule k3e9_5646fec9cc000b2a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5646fec9cc000b2a"
     cluster="k3e9.5646fec9cc000b2a"
     cluster_size="793 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre bfxq badur"
     md5_hashes="['c3bf98e7106c7fb9be0543f69a7c74c4', '5e2a01a812d3a210985133781f04a32a', 'b93efd6fe3ebe941de12bebbf18687ef']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13441,1067) == "f0b1679c76e37931d67a04f45677ba2c"
}

