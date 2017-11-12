import "hash"

rule m3e9_3a58b97b90bf4b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a58b97b90bf4b14"
     cluster="m3e9.3a58b97b90bf4b14"
     cluster_size="80 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="otwycal wapomi vjadtre"
     md5_hashes="['663c680f9b2c1e3a794331c9d389fc3f', 'be2ca8cf612c730aeacfe969e5cd3c6b', 'b4fa4f5fd14b4932d6acd4170b34cf8e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

