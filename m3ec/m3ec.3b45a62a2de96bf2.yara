import "hash"

rule m3ec_3b45a62a2de96bf2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.3b45a62a2de96bf2"
     cluster="m3ec.3b45a62a2de96bf2"
     cluster_size="4234 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hacktool kmsauto tool"
     md5_hashes="['2c23da20f4bb80f5170cef49f68f2dae', '2a56f2afd1fded3828537cff9242abc2', '0694d2f86b485354081f1cfd7d1116da']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(216064,1024) == "80223dd2b6bc15d58b671249a1c05afa"
}

