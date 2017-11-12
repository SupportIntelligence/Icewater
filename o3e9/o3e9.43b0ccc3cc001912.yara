import "hash"

rule o3e9_43b0ccc3cc001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0ccc3cc001912"
     cluster="o3e9.43b0ccc3cc001912"
     cluster_size="5300 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="parite madang small"
     md5_hashes="['346f9578ee3dcd32307c910ab0614811', '1ccfba2e791960f7df67caf9b1bcd3a3', '29413ce9165dec90dd531a956eb870be']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

