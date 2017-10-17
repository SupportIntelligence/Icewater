import "hash"

rule n3e9_4b99816fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b99816fc6220b12"
     cluster="n3e9.4b99816fc6220b12"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['883b792244749b27a713e41b52e4f055', '34b94187cd4cd868f86b14d1ed8abd4d', '6bf9b1a0e87634c5e5a9f57cb7408f99']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(453478,1046) == "43ca2b90a3960693e6a65891cb36aff2"
}

