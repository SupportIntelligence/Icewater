import "hash"

rule m3ec_199924d4dee30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.199924d4dee30932"
     cluster="m3ec.199924d4dee30932"
     cluster_size="4229 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="hackkms archsms hacktool"
     md5_hashes="['0a30b071184ccb3529ca9e72a810bb84', '00c170449b4775982c6f715611751bdd', '0a487a62edd46ec2f6fdcf47d1a09e04']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123904,1024) == "341199b87b62f9400e85d6910500c9cd"
}

