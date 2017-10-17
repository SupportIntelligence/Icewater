import "hash"

rule o3e9_29124422d7930912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29124422d7930912"
     cluster="o3e9.29124422d7930912"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="pwsime rootkit malicious"
     md5_hashes="['a29324599770cd868552298a9242dd3d', 'd449eecd0a4a96bd50b732a48dd52754', 'a410a778e7d6a557f96bc9c6c4aebb0e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2438500,1026) == "0367628e2d537af57b6871ab760132af"
}

