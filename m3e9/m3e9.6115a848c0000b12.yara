import "hash"

rule m3e9_6115a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6115a848c0000b12"
     cluster="m3e9.6115a848c0000b12"
     cluster_size="1174 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['785f38c5cad42ba64f0ad8dc6da6b3a7', '597b3dfffef18c3197a5b2b295319cc1', '658c939954ab11751f1c94a4bd182654']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

