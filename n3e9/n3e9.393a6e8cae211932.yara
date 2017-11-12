import "hash"

rule n3e9_393a6e8cae211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.393a6e8cae211932"
     cluster="n3e9.393a6e8cae211932"
     cluster_size="442 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4da1f16b06579fcd5a86b53ad5410e01', 'd428fe08e4de3e8a2b2bb25758935aa6', 'ab440514cfe95aa6cb864e710c4d84cc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(66048,1024) == "39d1c243962847d919cbdbe6cd412b87"
}

