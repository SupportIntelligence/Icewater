import "hash"

rule n3e7_439e908dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.439e908dc6220b12"
     cluster="n3e7.439e908dc6220b12"
     cluster_size="120 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="damaged file corrupt"
     md5_hashes="['fee117ed10df6e96ef1512f84a3f7ffd', '89118c980bffc5358124562f76a74ae8', '8a9e90f385f7eeb11a63735ba4f9c8b5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(35840,1024) == "25528b031edae36388929a5da006cde5"
}

