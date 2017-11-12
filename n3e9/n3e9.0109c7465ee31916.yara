import "hash"

rule n3e9_0109c7465ee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c7465ee31916"
     cluster="n3e9.0109c7465ee31916"
     cluster_size="2467 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious syncopate moderate"
     md5_hashes="['22ff31be2e48fefbe0de2271ad996ee9', '089bbc330a50000ab3f01e0e8670eb03', '0a1301b5e548c81d51344c417ed56c77']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "81501d626e5d4c6c4d7dd0223334ce12"
}

