import "hash"

rule k3e7_633d1e6948000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.633d1e6948000b12"
     cluster="k3e7.633d1e6948000b12"
     cluster_size="314 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit corrupt corruptfile"
     md5_hashes="['989cbe01e88857f549f6b2e35b0ebbdc', '2ed3f44fb2ab76581574869fb7a76c7b', '87010f63357a8db84f59fa0f7b4c511c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11264,1024) == "832555a3d176d3c8072432c503de6ae3"
}

