import "hash"

rule n3e9_499a856fc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499a856fc6220b32"
     cluster="n3e9.499a856fc6220b32"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['de5eebd9817a213b33564946602bc45c', 'de5eebd9817a213b33564946602bc45c', '1e19b9f78940a3518f85768803a621c8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(453478,1046) == "43ca2b90a3960693e6a65891cb36aff2"
}

