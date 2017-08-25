import "hash"

rule m3e9_16d199294a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d199294a9664f2"
     cluster="m3e9.16d199294a9664f2"
     cluster_size="1328 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="razy shipup zbot"
     md5_hashes="['0ccb9463625a54b51a76c1c952a8d5c6', '14b9429af801ba1066528f809d3d02f4', '5d018616cf08da1ad21b615972315aec']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(212480,1536) == "ed8b98743f3a32a3933347ead3f37b8d"
}

