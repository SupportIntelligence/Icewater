import "hash"

rule n3e9_0109c7465ee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c7465ee31916"
     cluster="n3e9.0109c7465ee31916"
     cluster_size="1505 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="malicious syncopate moderate"
     md5_hashes="['1203bc9f0d6a6cf9a8e8fbf4f17cec90', '0441765425c174459896ba0f8f2799cc', '2dfa10267d8bdba992f41348e17c96b5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "81501d626e5d4c6c4d7dd0223334ce12"
}

