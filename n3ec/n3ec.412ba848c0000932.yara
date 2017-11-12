import "hash"

rule n3ec_412ba848c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.412ba848c0000932"
     cluster="n3ec.412ba848c0000932"
     cluster_size="18577 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hacktool kmsauto tool"
     md5_hashes="['02ea650e7a2bb099d1a30511666b7be2', '0621b09fc9b54813bb14821cfe11e5c2', '049926bbd843c11f210bc839023e191d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(188216,1037) == "64ad8448c6b8cf2e3e13ad1d72cba5d7"
}

