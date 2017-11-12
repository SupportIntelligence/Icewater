import "hash"

rule n3e9_29c68558d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c68558d982e313"
     cluster="n3e9.29c68558d982e313"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor cuegoe malicious"
     md5_hashes="['bec7d5644e38f3f5f8b8cb10f712d7de', 'be2be333debb2eb007b0a9d84a6dd557', 'bbb7005c4ec0aa2cf0e43acf4939edb8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(808448,1076) == "ab5c78a222b72df8502930b7c2966067"
}

