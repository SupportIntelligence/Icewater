import "hash"

rule k3e9_45b4fc56dabb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc56dabb1932"
     cluster="k3e9.45b4fc56dabb1932"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['840c85f539cc7d55e4b2a299fdd232f9', 'ca42d7e0382c543da78c05b33f2d5b70', 'ca42d7e0382c543da78c05b33f2d5b70']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

