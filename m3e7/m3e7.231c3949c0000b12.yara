import "hash"

rule m3e7_231c3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.231c3949c0000b12"
     cluster="m3e7.231c3949c0000b12"
     cluster_size="222 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['b1b35ad73c7c1846fd6d28ccc34cd85c', 'e31ba6889d0fa6c0cb68bba5c61743ff', 'a15376dce5500472a964ca16ee0f7f01']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62090,1058) == "2cc91028f6f559f9c633c41bba0674cd"
}

