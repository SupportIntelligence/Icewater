import "hash"

rule n3fd_1b14e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.1b14e448c0000b32"
     cluster="n3fd.1b14e448c0000b32"
     cluster_size="342 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy malicious attribute"
     md5_hashes="['0cbb5f167d2569ac4ed1b2374d42c495', '0d56e6272e68c07f40ca962f4f07324d', '1fe4021e39b7d9bb29eeb73af2cfb9ae']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(266752,1536) == "ce7f9169fc612cd666a3eb2af2f4ced2"
}

