import "hash"

rule m3ed_6b322b25ddbb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b322b25ddbb1912"
     cluster="m3ed.6b322b25ddbb1912"
     cluster_size="103 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b15817391fa3374b3f6b0e1f300cf1e9', 'c87dcd65f082c1fc9ba4e1293c37b3ca', 'ed81da54d403809f9c4572d0118b1fbc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

