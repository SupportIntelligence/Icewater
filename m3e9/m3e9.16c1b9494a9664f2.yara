import "hash"

rule m3e9_16c1b9494a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c1b9494a9664f2"
     cluster="m3e9.16c1b9494a9664f2"
     cluster_size="96 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['c1b63c73320fd0d455d8e31a83450d45', '392c824dbc059684d53d9459a131d908', 'd32ace937a9a9453e2148824e21ac920']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(221184,256) == "be05042a99d973e40089853814e9dd5a"
}

