import "hash"

rule m3ed_5362115bdaef4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.5362115bdaef4912"
     cluster="m3ed.5362115bdaef4912"
     cluster_size="2333 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="browsefox riskware kozaka"
     md5_hashes="['00630de7ce8077d24318950b1b8ab74f', '0260cd06fbf03d1b4250ab83c812e83b', '037f66381ee0526259e26d364ef1ec22']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(179712,256) == "9275d14430661b4402e6407ffcdb73db"
}

