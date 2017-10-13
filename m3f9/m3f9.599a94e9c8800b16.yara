import "hash"

rule m3f9_599a94e9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.599a94e9c8800b16"
     cluster="m3f9.599a94e9c8800b16"
     cluster_size="1524 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bqau tiny vflooder"
     md5_hashes="['2a40183183da73f09565db4828fa7800', '1786bfd9809da93400f68d88950c3044', '2dabb65f106e8adf67e3020688d8dbf3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(105814,1194) == "49fb114f595141cf8954defa6a6d4922"
}

