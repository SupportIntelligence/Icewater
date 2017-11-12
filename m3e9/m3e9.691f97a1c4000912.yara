import "hash"

rule m3e9_691f97a1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f97a1c4000912"
     cluster="m3e9.691f97a1c4000912"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['cc07a1807802375f1e4cbf648912a066', 'c6b37d9ffcf76e07a19b83e667669e4d', 'a058313108daff69bdb23180f8437e07']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

