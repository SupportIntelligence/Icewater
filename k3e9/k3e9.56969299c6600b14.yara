import "hash"

rule k3e9_56969299c6600b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.56969299c6600b14"
     cluster="k3e9.56969299c6600b14"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2c41eb5c61556753081fc3d42089b170', '42cb88f992b56d8e9d2e20a96839e725', '9ae55bba96043705d78fd5c79db09546']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(2048,1024) == "f1ce8d7e7f91199173f2c298214ee3c3"
}

