import "hash"

rule n3e9_54a945a69ebb0130
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.54a945a69ebb0130"
     cluster="n3e9.54a945a69ebb0130"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="heuristic highconfidence malicious"
     md5_hashes="['ad8b13a07e3be5207cb6b88c07a626d7', 'e1fb4fd3cdf0ab89b01f3794f8d472ef', '0cea74e501a4ec7706bf9a4e90f58c2e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(71168,1024) == "d5ee76e2bd74f4d0ca78e3ab37799753"
}

