import "hash"

rule m3f0_5343eac9c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.5343eac9c0000912"
     cluster="m3f0.5343eac9c0000912"
     cluster_size="8102 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="blocker ransom drolnux"
     md5_hashes="['0a63503b3a1516f5e9a8c4fe6696510a', '090f92e466fdb8f4e38b5cadcedea693', '08ec052e09e81690bce8bb62de45390c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42496,1024) == "8ce80003e6cfc2ee76a6591ffe697c45"
}

