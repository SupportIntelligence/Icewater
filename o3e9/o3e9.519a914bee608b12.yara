import "hash"

rule o3e9_519a914bee608b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.519a914bee608b12"
     cluster="o3e9.519a914bee608b12"
     cluster_size="60 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious eheur high"
     md5_hashes="['3b43d6b4b5adefb84cc2741118f61fb5', 'd17925576bce416b8747353c1d92bd14', '1a5942ce90e77336f447fc7906d31447']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2166272,1038) == "a3d3dad22b8547f94e43f953d8450dee"
}

