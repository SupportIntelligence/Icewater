import "hash"

rule k3e9_45b4fc76dabb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc76dabb1932"
     cluster="k3e9.45b4fc76dabb1932"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d1064195fdd019a50999c74201ed0be3', 'd2f423c67265268279b9e4cfbf4e1a83', '1ef1cf5b3b81633c1bccba5e4ecb07ea']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(20480,1280) == "3e6f4cfcf731d063cebc1073d9d20cf0"
}

