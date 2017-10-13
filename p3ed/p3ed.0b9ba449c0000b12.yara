import "hash"

rule p3ed_0b9ba449c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.0b9ba449c0000b12"
     cluster="p3ed.0b9ba449c0000b12"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['1070391e515f0a8950d182331bfed4ee', '2a5f81894149465df33db5e79b1691a8', '4a58d2d9f6067f53c79a41e1da81a469']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(5057024,1024) == "5139ae1ab206610aedce3886ca7bd582"
}

