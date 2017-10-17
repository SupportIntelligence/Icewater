import "hash"

rule m3ec_5136cdf2f9811932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.5136cdf2f9811932"
     cluster="m3ec.5136cdf2f9811932"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['22d746541055aefb1babfa85e5d5e67d', '22d746541055aefb1babfa85e5d5e67d', '766c9bf3a7bf31b2642abee01ab88424']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100352,1536) == "292b1d29945fe470d6778f897ad36e0e"
}

