import "hash"

rule o3e9_4d66eac9c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4d66eac9c0000932"
     cluster="o3e9.4d66eac9c0000932"
     cluster_size="2703 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="startpage malicious adsearch"
     md5_hashes="['0791bb5f39484fd1ade117489e095d16', '05c8850d496725bf961f4a8d9f00f7ee', '0582879c2da73ba3d9335be77cae6aba']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(352403,1097) == "c26dc79e73edce35767a24d423b80ec7"
}

