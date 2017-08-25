import "hash"

rule m3ec_393ebd49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.393ebd49c0000912"
     cluster="m3ec.393ebd49c0000912"
     cluster_size="31729 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="antavmu fileinfector squdf"
     md5_hashes="['0166464411d43f3160446965be38123b', '024c086f3b0ec3c517d9943de96400cc', '00d793a2503cc6c63ac19a9b40f96c3f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(69120,1024) == "1842b898f669fbdd8d01bebadd096d53"
}

