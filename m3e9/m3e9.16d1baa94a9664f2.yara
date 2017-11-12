import "hash"

rule m3e9_16d1baa94a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1baa94a9664f2"
     cluster="m3e9.16d1baa94a9664f2"
     cluster_size="2661 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup razy zbot"
     md5_hashes="['33918966f3ae2994853defec39e30869', '1d31723469d63b322990c56755714de5', '2a7915e439ee77bd5c01b73306434a37']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(205298,1026) == "be5067a04c80e3830889c3baaa7d8293"
}

