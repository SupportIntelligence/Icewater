import "hash"

rule k3e9_45b4fc26debb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc26debb1932"
     cluster="k3e9.45b4fc26debb1932"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['19a19cdf18085fc2b07ee31cec829593', 'ed4e559dae8b35002782eef4b09d21ec', '05d8edccecfe2e22b8cc6414a5862eb9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

