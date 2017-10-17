import "hash"

rule m3ec_5696e119c2200b34
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.5696e119c2200b34"
     cluster="m3ec.5696e119c2200b34"
     cluster_size="375 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4704e08cf3f5777cc527716c14b63b47', 'e91fd833eee64affa4de55793f482f80', '8b2600abec787695666e5978852da5dc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(79360,1024) == "6bdb5569269545c5394c7880957704ac"
}

