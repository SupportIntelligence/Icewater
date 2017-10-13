import "hash"

rule o3e9_71919da1ca000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.71919da1ca000932"
     cluster="o3e9.71919da1ca000932"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality bakc beygb"
     md5_hashes="['caae43f3f398e5c473b125c2565a6c20', '2f011756fba390cb27c127a33e549cab', 'caae43f3f398e5c473b125c2565a6c20']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1052118,1066) == "16597b8474f77f1d939a748cf17f75f5"
}

