import "hash"

rule m3e9_16d199294a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d199294a9664f2"
     cluster="m3e9.16d199294a9664f2"
     cluster_size="1360 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy shipup zbot"
     md5_hashes="['5407a6658275ef044ea01a43e31d7d03', '06db0cc11002c690f6d153dbf1595ee6', '085090bf5f54b34661715cce5838f21f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(212480,1536) == "ed8b98743f3a32a3933347ead3f37b8d"
}

