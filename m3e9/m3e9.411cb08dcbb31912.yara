import "hash"

rule m3e9_411cb08dcbb31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411cb08dcbb31912"
     cluster="m3e9.411cb08dcbb31912"
     cluster_size="4555 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="startpage aaed qhost"
     md5_hashes="['03179be0e67b2bde76ea8d1753929b62', '022013983357f6ab1e9d1d8aee6d7c65', '0d054157ce1e6654569cd951dd3ae850']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(143360,1024) == "4ae051e69ba36d2fd93411968151b64e"
}

