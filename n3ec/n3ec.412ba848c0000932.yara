import "hash"

rule n3ec_412ba848c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.412ba848c0000932"
     cluster="n3ec.412ba848c0000932"
     cluster_size="13950 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="hacktool kmsauto tool"
     md5_hashes="['02990926794ab4252c9cff5fd6ca9762', '03021db0ca423330b22fd31cb506e096', '00f51e10d6f9be243ab5474b6b880dde']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(188216,1037) == "64ad8448c6b8cf2e3e13ad1d72cba5d7"
}

