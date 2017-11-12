import "hash"

rule n3e9_29c68b58d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c68b58d982e313"
     cluster="n3e9.29c68b58d982e313"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor cuegoe malicious"
     md5_hashes="['dd67cf64d69f2b0069d0c1b354d4528b', 'dd67cf64d69f2b0069d0c1b354d4528b', 'cd1255af0394de6dea7b272d1817ede1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1ebf251d64af3760403e40a9f3e8a108"
}

