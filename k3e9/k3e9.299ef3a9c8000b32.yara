import "hash"

rule k3e9_299ef3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299ef3a9c8000b32"
     cluster="k3e9.299ef3a9c8000b32"
     cluster_size="261 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['9ca941307a5878ed201a99cda49f4bd8', 'c6f662e8abb3ffcd3b5d774f78711d03', 'cb6a81acde6233650e6125168929bfa7']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

