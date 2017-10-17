import "hash"

rule n3ed_21b0c98278a14c5a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.21b0c98278a14c5a"
     cluster="n3ed.21b0c98278a14c5a"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bpchjo"
     md5_hashes="['1016e6f2e3fb92a970d6da9c339119f7', '1016e6f2e3fb92a970d6da9c339119f7', '0ffb3e53da192a4e026c587936192848']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(714752,1024) == "7fed6e3c154f3e373c9a0ebfd1940215"
}

