import "hash"

rule m3e9_6d14dee9c6400b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6400b12"
     cluster="m3e9.6d14dee9c6400b12"
     cluster_size="2405 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi swisyn abzf"
     md5_hashes="['4b34d3feb604adc5f402c8d21664181e', '85b39513f4cbb2e8f3c1a6e4ee964b04', '3ed40ff9ae7f06b799f1e51e96dcd833']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(26624,1024) == "f34865af21537c41ff5fcd9c4707274a"
}

