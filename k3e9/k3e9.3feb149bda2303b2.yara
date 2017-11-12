import "hash"

rule k3e9_3feb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3feb149bda2303b2"
     cluster="k3e9.3feb149bda2303b2"
     cluster_size="4019 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik trojandownloader"
     md5_hashes="['23451ca9034105d0d8e8f5f235044d35', '12ea4e60a88480fd451976c5876ab534', '06a706f67f1a65483707adc20f2b8d49']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(35840,1024) == "e838d409639bc516b49e963a461002ea"
}

