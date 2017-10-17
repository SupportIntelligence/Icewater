import "hash"

rule n3e9_421ebd49c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.421ebd49c4000b16"
     cluster="n3e9.421ebd49c4000b16"
     cluster_size="689 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef wbna"
     md5_hashes="['bfeb8123160a5763563da2d042cc16c7', 'b5e5f22a58c6a3db3742e39e02573574', '7fccbf2d6dc9f9397056bc174bf676dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(285756,1024) == "55aa32ec413c176adc09d0020ab6bcf9"
}

