import "hash"

rule m3e9_5114f7145ee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5114f7145ee31912"
     cluster="m3e9.5114f7145ee31912"
     cluster_size="926 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['218a094328846b898f7381548bea60b9', '864a369d2032cfa5f728d91455814b5c', '1f963dc18849784350c94f93952155b6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(75776,1536) == "122cbb75d0fd409647be64f54a4238ca"
}

