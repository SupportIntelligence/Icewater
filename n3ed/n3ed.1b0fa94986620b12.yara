import "hash"

rule n3ed_1b0fa94986620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b0fa94986620b12"
     cluster="n3ed.1b0fa94986620b12"
     cluster_size="1841 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['5a377a3259a772f3ca18c2ebfd6a02d8', '49388b139258abbc2a7a62a2b2e0f7c4', '1abdba6c7fc56a7f2a39515a232447a5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(296995,1059) == "529f9aec791a33f80d7be972c607e7b7"
}

