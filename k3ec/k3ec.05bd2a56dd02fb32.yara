import "hash"

rule k3ec_05bd2a56dd02fb32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.05bd2a56dd02fb32"
     cluster="k3ec.05bd2a56dd02fb32"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['bb5ae8ad9e284dbe06949a20c582fdcc', '83c4b061a75909f1f8d46690f9d0a37d', '83c4b061a75909f1f8d46690f9d0a37d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1280) == "7cbbd492fff018f31eb14c6a9c3166e9"
}

