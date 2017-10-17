import "hash"

rule n3ed_5c1ea91dc6600b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c1ea91dc6600b32"
     cluster="n3ed.5c1ea91dc6600b32"
     cluster_size="92 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['bbe6fb092db74b3e9c13c90980cc07df', 'a33301260b3af9f90be7975b39805dbb', 'cf826ced33d093df76ef13a4d431592d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(332800,1024) == "3eacbc4fc001d21d7f6b60c8cb4d7a59"
}

