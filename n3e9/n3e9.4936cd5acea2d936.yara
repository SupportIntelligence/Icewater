import "hash"

rule n3e9_4936cd5acea2d936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4936cd5acea2d936"
     cluster="n3e9.4936cd5acea2d936"
     cluster_size="709 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob browsefox"
     md5_hashes="['a32b646a1968e997a2db93bb240a361a', 'a455fd1704920548e8169c635d91bc4f', 'b3f2fa47802fe9d61d2dab0343a09b3d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(650934,1046) == "8a1cd3f9637826acac30d4de104604e9"
}

