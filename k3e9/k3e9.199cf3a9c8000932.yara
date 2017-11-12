import "hash"

rule k3e9_199cf3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.199cf3a9c8000932"
     cluster="k3e9.199cf3a9c8000932"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['d44d3a53f0b303bab683da9814c23947', 'c71ea6fc7051bf9228b156c843aa9e09', 'b66e395896cba2da9de5403ccb5b9a96']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

