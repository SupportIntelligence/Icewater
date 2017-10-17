import "hash"

rule n3ed_61c4ea49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.61c4ea49c0000b32"
     cluster="n3ed.61c4ea49c0000b32"
     cluster_size="59 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cb8adc4c208e9af331deac81288d0745', 'cb8adc4c208e9af331deac81288d0745', 'aff006607a7a2676cb26eb0285885191']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

