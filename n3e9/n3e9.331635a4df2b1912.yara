import "hash"

rule n3e9_331635a4df2b1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.331635a4df2b1912"
     cluster="n3e9.331635a4df2b1912"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious fvyj heuristic"
     md5_hashes="['491245c38688b206fdf439b64e628c16', '6b23bd31ce5f49a5f92925afb2a7928e', '294974cd32ede4e8be6a69770f09d86f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(9216,1024) == "67d377a97488450b3492b3301d87176f"
}

