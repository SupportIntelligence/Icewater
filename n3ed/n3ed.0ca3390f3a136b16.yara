import "hash"

rule n3ed_0ca3390f3a136b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f3a136b16"
     cluster="n3ed.0ca3390f3a136b16"
     cluster_size="118 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c83ebcb283a69d6255a41222f120fae8', 'b2c658b2b237fbf11d3bef08c702e14c', 'd4cff6772b1c6c4347fba5ed66120e75']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

