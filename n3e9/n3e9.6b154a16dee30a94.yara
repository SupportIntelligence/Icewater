import "hash"

rule n3e9_6b154a16dee30a94
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6b154a16dee30a94"
     cluster="n3e9.6b154a16dee30a94"
     cluster_size="2717 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor shiz razy"
     md5_hashes="['06a50d09140a5841bb366ba9a82f5920', '06a1216d7f295863edc57e02ce198621', '0824c7f4db9197b938d66c3fc804f5f6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(98304,1230) == "e5afe70561dbf1109a378cc52326c944"
}

