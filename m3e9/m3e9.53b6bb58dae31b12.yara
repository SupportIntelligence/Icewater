import "hash"

rule m3e9_53b6bb58dae31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53b6bb58dae31b12"
     cluster="m3e9.53b6bb58dae31b12"
     cluster_size="140 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c0759ba3129a8ea8a9b75017e76cc428', 'ceb0bad5cb251b9f0d31a8c1c9d3848e', 'e796017c4bf510fd8202ad36ffb2e8dc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80896,1280) == "c23266a7380bf3daa3a8422c6d2fd0c8"
}

