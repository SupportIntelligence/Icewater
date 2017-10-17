import "hash"

rule n3ed_51996b6699a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b6699a31932"
     cluster="n3ed.51996b6699a31932"
     cluster_size="115 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['507e98496da3bb08e05a818104640629', '20b3621e61bdefcf8b8a63864f33747e', 'b2a2fe40e29a709d4cc3b38b65f7027f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

