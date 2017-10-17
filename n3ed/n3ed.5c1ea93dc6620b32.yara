import "hash"

rule n3ed_5c1ea93dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c1ea93dc6620b32"
     cluster="n3ed.5c1ea93dc6620b32"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['adf0264a6514d4dd13773479ba31347f', 'ba5f724ba9562642dab6fe64fef67381', '5c58f005e6bdc8b25f4c1b3d80597fd4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(332800,1024) == "3eacbc4fc001d21d7f6b60c8cb4d7a59"
}

