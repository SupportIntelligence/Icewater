import "hash"

rule k3e9_42146124dda30b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42146124dda30b10"
     cluster="k3e9.42146124dda30b10"
     cluster_size="97 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ad118dad5112db3632bbfca561321357', '4df7551f3558a5a1bf5e7cb9a92786f3', 'c60fa32321b737b8be44bf39e5cbb75c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5236,1053) == "f906a3bcdc2f7c6cc54ba5e3cf5278e7"
}

