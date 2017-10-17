import "hash"

rule n3ed_3134408cfa230912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.3134408cfa230912"
     cluster="n3ed.3134408cfa230912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['4315ceb2f37fe867571716642aeca1a7', '4315ceb2f37fe867571716642aeca1a7', 'bb8716f80f73da7e7bb4e7c94c1f08b8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

