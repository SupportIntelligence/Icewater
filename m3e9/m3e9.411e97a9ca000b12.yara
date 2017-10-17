import "hash"

rule m3e9_411e97a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411e97a9ca000b12"
     cluster="m3e9.411e97a9ca000b12"
     cluster_size="134 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['deef48a3e91c996adcefd2c9dbcde804', 'ce6b044255f32cf0c122d202fc1d2bcf', '1c3eac25cecf1f3646cb7bc8d2107446']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73291,1029) == "da5ab260d3f3b2aa7508f7dfc1ddb857"
}

