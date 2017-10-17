import "hash"

rule m3e9_169b14cdcac5405a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.169b14cdcac5405a"
     cluster="m3e9.169b14cdcac5405a"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['33f06c6cd64ac7b3ef49722cbb372d7e', 'a5a482acc8bf9e48345c98329f5f0c7d', '80e73441a4968758d9f4b97ec2a0193d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "8d58ed16906ae198e8c0039b79b0e709"
}

