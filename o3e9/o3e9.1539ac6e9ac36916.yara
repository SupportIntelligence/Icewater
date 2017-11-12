import "hash"

rule o3e9_1539ac6e9ac36916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1539ac6e9ac36916"
     cluster="o3e9.1539ac6e9ac36916"
     cluster_size="364 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster malicious attribute"
     md5_hashes="['348458e180810a0c76a2f0e8e6c48f20', '16a6fd88aad7f5da841ae1d48ee65bca', '70e902041ad351cfa89505680d18ff44']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2699264,1024) == "cbb496e1b0693d164266e5c6dc54dac3"
}

