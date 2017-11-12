import "hash"

rule k3e9_139da1e499991932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da1e499991932"
     cluster="k3e9.139da1e499991932"
     cluster_size="21513 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nimnul vjadtre wapomi"
     md5_hashes="['06e5d7e0e9eb2effac6f84217c4df3f9', '046b183940605c8f3bca4cff70854e91', '047d1c2db38822964648e117e96c40c8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

