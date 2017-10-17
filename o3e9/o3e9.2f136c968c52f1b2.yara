import "hash"

rule o3e9_2f136c968c52f1b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2f136c968c52f1b2"
     cluster="o3e9.2f136c968c52f1b2"
     cluster_size="187 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['a1f1ff3a141021318faa86d5ada718c0', '2e3f82200d828448cc8e99277b23505c', 'c023854c8f409be24b2ea817fe9726d3']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1725440,1024) == "b1ac007303f77b2ddd946181deba8128"
}

