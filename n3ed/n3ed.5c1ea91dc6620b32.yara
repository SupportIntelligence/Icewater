import "hash"

rule n3ed_5c1ea91dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c1ea91dc6620b32"
     cluster="n3ed.5c1ea91dc6620b32"
     cluster_size="166 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['bae61b66d0815c9a4f5158f411247513', 'deb7d12fc6c91ef49a7b0ea22184706b', 'e916d51d61c02595ef9ec530366b3514']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(355328,1024) == "42907834ef8f6943aa99fc9df9b14624"
}

