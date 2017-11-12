import "hash"

rule k3e9_45b4fc26ddbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc26ddbb1932"
     cluster="k3e9.45b4fc26ddbb1932"
     cluster_size="17 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['be278abe15e2d5a0ef6a157e4dc15933', 'd79d448d51aa128d3c927abf44537b05', 'be278abe15e2d5a0ef6a157e4dc15933']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

