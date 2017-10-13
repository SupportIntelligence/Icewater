import "hash"

rule m3e9_611c95c9c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c95c9c6620b32"
     cluster="m3e9.611c95c9c6620b32"
     cluster_size="396 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sirefef vobfus diple"
     md5_hashes="['b07b582b161dc0c1776cac3695c26223', '857af4952b40593ba00bdfe76fd8346c', 'bb2f38b150c5df65204825b5a83ba96b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(110592,1024) == "843aab3a5fe43eed6a8622faf29e3ceb"
}

