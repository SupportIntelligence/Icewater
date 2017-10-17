import "hash"

rule m3e9_631e3689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631e3689c8000b12"
     cluster="m3e9.631e3689c8000b12"
     cluster_size="340 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['efaca5b790c23395ba477241f3595d7f', 'b697e13e56129ef78eddeae5c0027bf2', '81ce23af154e46b5c0e7f34dc1c8ecd9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62060,1051) == "6b92d4de5a9816ad40ab710f60080201"
}

