import "hash"

rule p3ed_115b9ac9c8001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.115b9ac9c8001932"
     cluster="p3ed.115b9ac9c8001932"
     cluster_size="761 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['86ad177e2e21865eb5e1c9f30606af31', '308b8e36032734919c65927bfc2d94d2', '7436b56ba94f5e3ef2d416211177b371']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4594176,1536) == "c848423a9ae2e84fcd837368f521bf2c"
}

