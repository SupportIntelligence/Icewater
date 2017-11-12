import "hash"

rule o3ed_635244cece439b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece439b12"
     cluster="o3ed.635244cece439b12"
     cluster_size="1787 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['ac2e365d0c2e1fab5b00c4e02ea59140', 'ac2e365d0c2e1fab5b00c4e02ea59140', 'a015c5d66873be6192f43108dd48d448']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2059264,1024) == "2a0101aaa8675aeef3b9f3602a30c8c9"
}

