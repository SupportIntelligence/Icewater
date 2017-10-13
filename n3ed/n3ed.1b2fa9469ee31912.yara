import "hash"

rule n3ed_1b2fa9469ee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa9469ee31912"
     cluster="n3ed.1b2fa9469ee31912"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cef550abae6ff679a5b76197c95a8cb4', 'da60c63ec279a0f24848704ffe14798b', '46e1bd4fe25ee884a0518b3e99290faf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "f3e36befd0755f24ecffaff8a4db5c6e"
}

