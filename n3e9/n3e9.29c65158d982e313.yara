import "hash"

rule n3e9_29c65158d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c65158d982e313"
     cluster="n3e9.29c65158d982e313"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious cuegoe"
     md5_hashes="['ef742fb867b96a10cb920d180b62b0d0', 'ab5e92e640337f0b07f80eee0b1363fa', '29591aa3afa5ac34146bab4f9abba89e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1ebf251d64af3760403e40a9f3e8a108"
}

