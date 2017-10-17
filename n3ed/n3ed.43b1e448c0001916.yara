import "hash"

rule n3ed_43b1e448c0001916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.43b1e448c0001916"
     cluster="n3ed.43b1e448c0001916"
     cluster_size="109 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy quchispy malicious"
     md5_hashes="['69fc358dd1a12294665419abf3e38acd', '85b90429100ee3953ba8ff0bd9cf229f', '518be3e0b7c2cb9bdc92f1949e8557c0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(238365,1043) == "94f5429adeb3d92a8375289550e4a1eb"
}

