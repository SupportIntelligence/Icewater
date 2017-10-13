import "hash"

rule m3e9_52aca6c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.52aca6c9c8000912"
     cluster="m3e9.52aca6c9c8000912"
     cluster_size="2351 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy tinba backdoor"
     md5_hashes="['a40ee18dad3f751aa0ac136df12fe8f7', 'a3ddad7d2c229542db4b037e8b39c370', 'a57ed1771636945c4de2211c13e952a4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(92160,1024) == "888ae8f4fa0ccdb6dc79f6b13f02ca20"
}

