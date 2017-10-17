import "hash"

rule o3ed_4a1c92b9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4a1c92b9c9800b12"
     cluster="o3ed.4a1c92b9c9800b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['b86c22eaf9283bdefcbe816d586f240a', 'b86c22eaf9283bdefcbe816d586f240a', 'b86c22eaf9283bdefcbe816d586f240a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

