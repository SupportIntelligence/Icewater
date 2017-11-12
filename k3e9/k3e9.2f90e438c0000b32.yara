import "hash"

rule k3e9_2f90e438c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2f90e438c0000b32"
     cluster="k3e9.2f90e438c0000b32"
     cluster_size="71 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bxvp trojanclicker small"
     md5_hashes="['d70fe01dbaf47273b0c822c992a85e52', '99dbc780e88580f35bd275b6757deb02', '75fa8097622cde4bb120198250f27fe2']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(17408,1024) == "a745d823052c2c66c10967651d915e35"
}

