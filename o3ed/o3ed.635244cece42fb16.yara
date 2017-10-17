import "hash"

rule o3ed_635244cece42fb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece42fb16"
     cluster="o3ed.635244cece42fb16"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d06251d7bab602875f3e5b5aa65fbca4', 'c0a5d5114e2a35c8a622fd8269bad331', 'a77c3be9e43727b1d536e137a031601a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2711552,1024) == "b76cb8f54dcda147685e3a189523f6b0"
}

