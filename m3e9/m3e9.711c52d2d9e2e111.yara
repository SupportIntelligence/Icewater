import "hash"

rule m3e9_711c52d2d9e2e111
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.711c52d2d9e2e111"
     cluster="m3e9.711c52d2d9e2e111"
     cluster_size="215 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c1cf30cd720dbb33f1dd788b974691c7', 'bf5327c57c7fbc7b9e8b7d872a1cab15', 'd0bc99b6e123947d8185525f39d14348']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(9216,1024) == "fbad040c0983c3d7c7a05e828ed77efb"
}

