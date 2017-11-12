import "hash"

rule n3e9_41165872da92d112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.41165872da92d112"
     cluster="n3e9.41165872da92d112"
     cluster_size="724 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['09b4c92a36be9ef1eb9116d0e73df8a2', '359e6c5e56c1158df23c2e0432d3392b', '250a1493f385b0636644b852394a6b66']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(458752,1024) == "e5d33ba27896e03112a8ca25650e2d9c"
}

