import "hash"

rule m3e9_5134f7145ee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5134f7145ee31912"
     cluster="m3e9.5134f7145ee31912"
     cluster_size="505 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d13df2e32c351f8d0b81d5fbcc9a8b80', 'a47be22d0d3afb8083072d64ced32c5d', '36973d2effc5cf97d4db94a6b1647c38']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(75776,1536) == "122cbb75d0fd409647be64f54a4238ca"
}

