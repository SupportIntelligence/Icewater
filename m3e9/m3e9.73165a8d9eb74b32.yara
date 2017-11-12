import "hash"

rule m3e9_73165a8d9eb74b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9eb74b32"
     cluster="m3e9.73165a8d9eb74b32"
     cluster_size="14875 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="swisyn bner mofksys"
     md5_hashes="['128d320caf7db5e76f8aa8e896d07306', '01e4d6be7f03bc099820a65a02331916', '05cd769d3d5dc751672a2f770fd8b42e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

