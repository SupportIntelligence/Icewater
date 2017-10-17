import "hash"

rule k3e9_6b66d36e0ab91112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d36e0ab91112"
     cluster="k3e9.6b66d36e0ab91112"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="aliser alisa small"
     md5_hashes="['1829d291b44eeadf8503b02e4420a068', '1829d291b44eeadf8503b02e4420a068', 'bb621c0ae2017b4147c2498bc7ed743a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1536) == "003ed58a9e86febc9235ff6d61ee4133"
}

