import "hash"

rule k3e9_53b933361da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.53b933361da31132"
     cluster="k3e9.53b933361da31132"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['5b732ca60e1f74f7c0b695c2d8eaa924', '6191d436c693dd26f14c514c37080ff1', '6191d436c693dd26f14c514c37080ff1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "954c86ae7531ecbf5554bcf2fd05309d"
}

