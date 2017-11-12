import "hash"

rule k400_14544f0ecfa3d332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.14544f0ecfa3d332"
     cluster="k400.14544f0ecfa3d332"
     cluster_size="1040 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="tinba razy malicious"
     md5_hashes="['5117ef6948a23b928409d6f1888043a3', '9ceb04ce5d6228a236e6418d64ce190e', '8169efa6de8a94842485be8be2348af3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(48470,1081) == "92e4d80b0ee2c5027e00d0973e66e3ad"
}

