import "hash"

rule n3ed_53129299c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53129299c2200b16"
     cluster="n3ed.53129299c2200b16"
     cluster_size="93 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d7c1ce03f4848073036f47014a3e965e', 'c1e9e80840971b26cbec20d3192e743c', '56e59bb870745aa019f612bf164ab723']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

