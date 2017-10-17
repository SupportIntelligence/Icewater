import "hash"

rule n3ec_2160d39bc6621132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.2160d39bc6621132"
     cluster="n3ec.2160d39bc6621132"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a895f36ddcb2e2a093ba988cb059c12e', '3836ef9ba8a27fa50ad05387b3a06313', 'da2e11614c6bc3ee6267482a9181678a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(69694,1026) == "25718501eb1efd80b11d18c5020f58a5"
}

