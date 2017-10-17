import "hash"

rule n3e9_4116acc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4116acc1c8000b12"
     cluster="n3e9.4116acc1c8000b12"
     cluster_size="1109 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mabezat tazebama avce"
     md5_hashes="['a0811ba44d241a23d4d2c17ed71c921c', '1ea015836cc87e74a9e3fe2a71e7c4f6', 'a72f380776dd9777c653629dbf6f325a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(36864,1024) == "04af7fc1f75562119d235351c88e0ad7"
}

