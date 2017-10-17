import "hash"

rule m3e9_42c6ccaba553e4b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.42c6ccaba553e4b2"
     cluster="m3e9.42c6ccaba553e4b2"
     cluster_size="197 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['f3cd23e8ae0c877e8e75901773c34619', 'cbdb44004c8c223adec809ccb04f8d38', 'caa81bfb7dad42ad91d7f768ecf3dd7d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(131072,1280) == "916a8ce03c708ee7a80ea7eb32550333"
}

