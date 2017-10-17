import "hash"

rule m3f0_08e469aec6210b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.08e469aec6210b12"
     cluster="m3f0.08e469aec6210b12"
     cluster_size="1804 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy kryptik shipup"
     md5_hashes="['a6dcaea7857c947d6032b30f18099801', '6e6a4f4b4b02f1ddd59149768851c48d', '4cbdf65f87982d0245d4c24ee41f2c3d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(130048,1536) == "dfb3600f3d78027d91f45e39c36a1675"
}

