import "hash"

rule n3ed_591385a7be211b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a7be211b32"
     cluster="n3ed.591385a7be211b32"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['9da43a964371524b7495b14256541d7a', '45e999f599b91939d4e7893eaf2480fd', '1ab6770cb6b2b17316104da4d5c4b131']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(418756,1036) == "210f6608b2efbfbe03110188284f4477"
}

