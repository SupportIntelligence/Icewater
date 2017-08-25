import "hash"

rule k3e9_17e309961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e309961ee31132"
     cluster="k3e9.17e309961ee31132"
     cluster_size="162 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b7a32e1c0fff75d940432881ca210d39', '349e15b8ca90340d472173fb9b8efc9c', 'aa48b33293ec69d32235dd4818f6aa5f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "2d0a794179422cbb47ac4f30a07f9908"
}

