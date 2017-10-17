import "hash"

rule o3e7_29b362dbb43be332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.29b362dbb43be332"
     cluster="o3e7.29b362dbb43be332"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster malicious installmonstr"
     md5_hashes="['4469ef4c3a17988bab38dc2ca1b99c85', '518fffaaace831ba12bcba307770e836', '518fffaaace831ba12bcba307770e836']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(50224,1025) == "71d10363c5104279a3b014a455ae04c1"
}

