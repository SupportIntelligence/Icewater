import "hash"

rule n3e9_3619b41dc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3619b41dc6620b14"
     cluster="n3e9.3619b41dc6620b14"
     cluster_size="346 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="auslogics unwanted gkrbja"
     md5_hashes="['aa59ae9ca953f6b5d08b9f5bc49853a0', '4315526138612fab4286a06f9b035e72', '40b2a10e5b3252c1f00339104cb72c1e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 262144 and filesize < 1048576
      and hash.md5(349696,1024) == "538363a4ea0fef632324399081c25270"
}

