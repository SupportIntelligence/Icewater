import "hash"

rule k3ed_15e66b9140000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.15e66b9140000932"
     cluster="k3ed.15e66b9140000932"
     cluster_size="270 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious proxy heuristic"
     md5_hashes="['5200921e409d3e736647389a55a112a3', 'c9fcec2fa60851bc3e3a08334449aac3', '72f8d2804ccf634f38b8d0171d662d71']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22016,1024) == "0e556c45df59d5b068511c8fe00a25a2"
}

