import "hash"

rule o3e7_14934c6b94394eba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.14934c6b94394eba"
     cluster="o3e7.14934c6b94394eba"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious heuristic installmonster"
     md5_hashes="['b42809ec8524c37b015673f637851e05', 'c020364da924194afe2c00c38ff9df1d', 'a8b6f6edad4c2e2527ceff31df1e88b3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3119104,1024) == "aaf57a10f5117ff1bbd4f71dc116ae17"
}

