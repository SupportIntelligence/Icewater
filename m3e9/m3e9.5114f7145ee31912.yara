import "hash"

rule m3e9_5114f7145ee31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5114f7145ee31912"
     cluster="m3e9.5114f7145ee31912"
     cluster_size="493 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9ecc900241bdb1b2583264da4282946d', '0868fd426eaaa0c9bdf334da84cd56e4', '946cca1ef7991b66eeae2f21d70ca8f9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(75776,1536) == "122cbb75d0fd409647be64f54a4238ca"
}

