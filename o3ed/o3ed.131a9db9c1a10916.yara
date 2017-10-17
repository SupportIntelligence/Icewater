import "hash"

rule o3ed_131a9db9c1a10916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9db9c1a10916"
     cluster="o3ed.131a9db9c1a10916"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['bd6994ad7661e1d54e4e9b341c7b28a0', '53e2e8115cd40e7a6984097addbf174b', '53e2e8115cd40e7a6984097addbf174b']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2183168,1024) == "0e6e52e26906a323049b5f94126f2295"
}

