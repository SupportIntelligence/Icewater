import "hash"

rule n3e9_47266d6cba211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.47266d6cba211932"
     cluster="n3e9.47266d6cba211932"
     cluster_size="383 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d57b348743a5956a18033a0041ca884a', '231e50dce29fe13c6481e5f99e31e1cc', 'edd0667656f45305fdc6a57e687939bf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(299008,1024) == "6948162505ebd9ad51cda4e52b2bc0b3"
}

