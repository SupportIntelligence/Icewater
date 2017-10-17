import "hash"

rule k3e9_05ba56d3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05ba56d3cc000932"
     cluster="k3e9.05ba56d3cc000932"
     cluster_size="935 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bublik generickd trojandownloader"
     md5_hashes="['a9881a3c18cdeff1560dfa7836ab556e', 'abe82e7f65a76bdd7f985bb4cae7aed3', '0d817d94bb00afdc425c7709371ee6a0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,1088) == "4f759379b23c048c84d0fc7a719712ae"
}

