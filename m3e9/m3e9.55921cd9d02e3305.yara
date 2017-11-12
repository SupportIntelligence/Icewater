import "hash"

rule m3e9_55921cd9d02e3305
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.55921cd9d02e3305"
     cluster="m3e9.55921cd9d02e3305"
     cluster_size="385 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bf352818dbacc1b6bba3824c54b997b5', 'ec1de8f6f90fe01719a4bd26bd8d5159', 'dc79e4145d0800987245c1504526bde1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(85504,1024) == "5fb24584ad81558081fe5cc5f2b668e8"
}

