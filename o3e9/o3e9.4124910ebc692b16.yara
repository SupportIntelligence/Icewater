import "hash"

rule o3e9_4124910ebc692b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4124910ebc692b16"
     cluster="o3e9.4124910ebc692b16"
     cluster_size="15902 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0855125dc1941c9bcdc70ee19ddd3d9a', '00d95f5fff9fb4536f9f128be596ac02', '08c46653ce9f6e2bdad98fcf5ec2c3ad']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2937004,1058) == "5273f25dc0a964c6f5423daf1554c19c"
}

