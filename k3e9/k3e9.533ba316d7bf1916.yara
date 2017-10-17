import "hash"

rule k3e9_533ba316d7bf1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.533ba316d7bf1916"
     cluster="k3e9.533ba316d7bf1916"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['3c6e8f97d08e228f16dd3d441e0e1c08', 'f44176bf4ea4ebbca85e2a6e8b1ef583', '69b6f3a6f3557a2b8340d69227355fa3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12800,1280) == "9bec7913a2600fdf8cf39f32c8126b0b"
}

