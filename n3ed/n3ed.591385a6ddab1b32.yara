import "hash"

rule n3ed_591385a6ddab1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6ddab1b32"
     cluster="n3ed.591385a6ddab1b32"
     cluster_size="81 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a19c3cb1a16e2e8eface3ba33bfe2434', 'dbf362d3bc33c78615cd4705c80fea3e', 'e3126f9edfcbd578c32cf797df99a918']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

