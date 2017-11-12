import "hash"

rule n3e9_31ca909982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca909982200932"
     cluster="n3e9.31ca909982200932"
     cluster_size="498 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['b4db0274057788943930b8f4d9d6bcc5', '3f723a7492074be883b527f73f39e20f', '2f1deebbcde1c2371806609cdfbad9d0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(160768,1024) == "7774b2f01cddaa39a7d8fd19f440508b"
}

